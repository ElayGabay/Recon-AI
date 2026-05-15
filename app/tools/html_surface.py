"""
Parse HTML from content probes: forms, links, JS URL literals, CMS hints.
Produces structured data + rows compatible with content_probe suspicious_params.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlparse, urljoin, urlunparse

# Stored on disk / passed to Ollama (keep prompts bounded)
MAX_HTML_EXCERPT = 32_000
MAX_PARSE_BYTES = 600_000

# Keep in sync with content_probe.SUSPICIOUS_* (avoid circular imports)
SUSPICIOUS_LFI_PARAMS = {
    "file", "page", "path", "include", "template", "view",
    "inc", "document", "doc", "folder", "load", "read", "show",
    "fetch", "dir", "display", "resource", "src", "source",
    "require", "import", "module", "conf", "config",
}
SUSPICIOUS_ALL_PARAMS = SUSPICIOUS_LFI_PARAMS | {
    "search", "q", "query", "id", "user", "name", "cmd", "exec",
    "redirect", "url", "next", "return", "target", "goto", "dest",
    "ref", "action", "type", "kind", "mode", "lang", "locale",
}


def is_internal_url(url: str, allowed_host: str) -> bool:
    parsed = urlparse(url)
    if not parsed.hostname:
        return True
    hostname = parsed.hostname.lower()
    allowed_host = allowed_host.lower()
    return hostname == allowed_host or hostname.endswith("." + allowed_host)


def normalize_discovered_url(base_url: str, raw_link: str) -> str | None:
    raw_link = raw_link.strip()
    if not raw_link:
        return None
    if raw_link.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    return urljoin(base_url, raw_link)


# --- Parameter → vulnerability-style tags (for brain + reporting) ---

_LFI = SUSPICIOUS_LFI_PARAMS
_SQLIISH = {"id", "user", "uid", "userid", "order", "sort", "column", "table", "row", "filter"}
_XSSISH = {"q", "query", "search", "s", "keyword", "term", "title", "name", "comment", "msg", "message", "html", "content", "text", "value", "data"}
_SSRFISH = {"url", "uri", "link", "src", "fetch", "proxy", "request", "endpoint", "callback", "webhook", "host", "domain", "path", "redirect", "next", "return", "goto", "dest", "target", "ref"}
_CMDISH = {"cmd", "command", "exec", "execute", "shell", "system", "run"}


def classify_param_categories(param_name: str) -> list[str]:
    n = (param_name or "").lower().strip()
    if not n:
        return []
    tags: list[str] = []
    if n in _LFI:
        tags.append("lfi")
    if n in _SQLIISH or n.endswith("_id") or n.startswith("id"):
        tags.append("sqli")
    if n in _XSSISH:
        tags.append("xss")
    if n in _SSRFISH:
        tags.append("ssrf_or_open_redirect")
    if n in _CMDISH:
        tags.append("command_injection")
    if n in SUSPICIOUS_ALL_PARAMS and not tags:
        tags.append("injection_surface")
    return tags or ["unknown"]


_META_GENERATOR = re.compile(
    r'(?is)<meta[^>]+name\s*=\s*["\']generator["\'][^>]+content\s*=\s*["\']([^"\']+)["\']',
)
_META_GENERATOR_REV = re.compile(
    r'(?is)<meta[^>]+content\s*=\s*["\']([^"\']+)["\'][^>]+name\s*=\s*["\']generator["\']',
)
_JS_URL_ASSIGN = re.compile(
    r"(?is)\b(root_url|root_admin_url|base_url|baseUrl|BASE_URL|api_url|apiUrl|API_URL|"
    r"backend_url|BACKEND_URL|endpoint_url|ENDPOINT|ajax_url|admin_url|ADMIN_URL)\b\s*[=:]\s*['\"]([^'\"]{2,512})['\"]",
)


def _strip_fragment(u: str) -> str:
    return u.split("#", 1)[0]


def _build_query_url(base: str, params: dict[str, str]) -> str:
    parsed = urlparse(base)
    q = urlencode(list(params.items()))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", q, ""))


def build_ffuf_lfi_url(action_url: str, field_names: list[str], fuzz_param: str) -> str:
    """Build GET URL with one query parameter set to FUZZ (for ffuf_lfi / lfi_triage)."""
    names = [n for n in field_names if n]
    if fuzz_param not in names:
        names.append(fuzz_param)
    params = {name: "FUZZ" if name == fuzz_param else "test" for name in names}
    return _build_query_url(action_url, params)


def extract_cms_and_js_hints(html: str) -> tuple[list[str], list[dict]]:
    cms: list[str] = []
    for rx in (_META_GENERATOR, _META_GENERATOR_REV):
        for m in rx.finditer(html[:200_000]):
            g = (m.group(1) or "").strip()
            if g and g not in cms:
                cms.append(g)
    low = html.lower()
    if "wp-content" in low or "wordpress" in low:
        if "WordPress (meta or paths)" not in cms:
            cms.append("WordPress (meta or paths)")
    if "drupal" in low or "sites/default" in low:
        cms.append("Drupal indicators")
    if "joomla" in low or "com_joomla" in low:
        cms.append("Joomla indicators")

    js_urls: list[dict] = []
    seen: set[str] = set()
    for m in _JS_URL_ASSIGN.finditer(html[:400_000]):
        var, val = m.group(1), (m.group(2) or "").strip()
        key = f"{var}:{val}"
        if key in seen or not val or val.startswith(("{", "${")):
            continue
        seen.add(key)
        js_urls.append({"variable": var, "value": val})
    return cms, js_urls


class _SurfaceHTMLParser(HTMLParser):
    def __init__(self, page_url: str, allowed_host: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.allowed_host = allowed_host
        self.forms: list[dict] = []
        self.links: list[dict] = []
        self._form: dict | None = None

    def _resolve(self, raw: str | None) -> str | None:
        if raw is None:
            raw = ""
        raw = raw.strip()
        if not raw:
            return _strip_fragment(self.page_url)
        low = raw.lower()
        if low.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        full = normalize_discovered_url(self.page_url, raw)
        if not full:
            return None
        full = _strip_fragment(full)
        if not is_internal_url(full, self.allowed_host):
            return None
        return full

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()

        if t == "form":
            action = self._resolve(a.get("action"))
            if action is None and (a.get("action") or "").strip():
                return
            if action is None:
                action = _strip_fragment(self.page_url)
            method = (a.get("method") or "get").upper()
            self._form = {"action_abs": action, "method": method, "fields": []}

        elif t == "input" and self._form is not None:
            name = (a.get("name") or "").strip()
            if not name:
                return
            itype = (a.get("type") or "text").lower()
            if itype in {"submit", "button", "image", "reset"}:
                return
            self._form["fields"].append({"name": name, "type": itype})

        elif t in {"select", "textarea"} and self._form is not None:
            name = (a.get("name") or "").strip()
            if name:
                self._form["fields"].append({"name": name, "type": t})

        elif t == "a":
            href = a.get("href")
            if not href:
                return
            full = self._resolve(href)
            if not full:
                return
            parsed = urlparse(full)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            self.links.append(
                {
                    "href": full,
                    "path": parsed.path or "/",
                    "query_keys": list(qs.keys()),
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def discover_html_surface(html: str, page_url: str, allowed_host: str) -> dict:
    """
    Parse HTML and return forms, links, CMS/JS hints, and suspicious_param-style rows.
    """
    allowed_host = allowed_host or (urlparse(page_url).hostname or "")
    snippet = html[:MAX_PARSE_BYTES]
    parser = _SurfaceHTMLParser(page_url, allowed_host)
    try:
        parser.feed(snippet)
        parser.close()
    except Exception:
        pass

    if parser._form is not None:
        parser.forms.append(parser._form)

    cms_hints, js_literals = extract_cms_and_js_hints(snippet)

    suspicious_rows: list[dict] = []
    lfi_fuzz_targets: list[dict] = []
    seen: set[tuple[str, str]] = set()
    seen_lfi_urls: set[str] = set()

    def add_lfi_target(
        action_url: str,
        param: str,
        field_names: list[str],
        source: str,
    ) -> None:
        ffuf_url = build_ffuf_lfi_url(action_url, field_names, param)
        key = ffuf_url.rstrip("/").lower()
        if key in seen_lfi_urls:
            return
        seen_lfi_urls.add(key)
        lfi_fuzz_targets.append(
            {
                "ffuf_lfi_url": ffuf_url,
                "param": param,
                "endpoint": action_url,
                "source": source,
            }
        )

    def add_row(
        u: str,
        param: str,
        source: str,
        *,
        from_get_form: bool = False,
        fuzz_any_name: bool = False,
    ) -> None:
        """Record a parameter; GET forms and in-page query links always qualify for LFI fuzz."""
        p = (param or "").strip()
        if not p:
            return
        pl = p.lower()
        if not from_get_form and not fuzz_any_name and pl not in SUSPICIOUS_ALL_PARAMS:
            return
        parsed = urlparse(u)
        key = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower(), pl)
        if key in seen:
            return
        seen.add(key)
        cats = classify_param_categories(p)
        suspicious_rows.append(
            {
                "url": u,
                "param": p,
                "lfi_candidate": pl in SUSPICIOUS_LFI_PARAMS,
                "categories": cats,
                "source": source,
                "suggest_ffuf_lfi": pl in SUSPICIOUS_LFI_PARAMS,
            }
        )

    # Forms → example GET URLs + param rows
    compact_forms: list[dict] = []
    for form in parser.forms:
        action = form["action_abs"]
        method = form["method"]
        names = [f["name"] for f in form["fields"] if f.get("name")]
        compact_forms.append(
            {
                "action": action,
                "method": method,
                "field_names": names[:40],
            }
        )
        if method != "GET" or not names:
            continue
        placeholder = {n: "test" for n in names}
        example = _build_query_url(action, placeholder)
        for n in names:
            add_row(example, n, "html_form_get", from_get_form=True)
            # LFI scheduling is handled by param_discovery (confidence + response tests)

    # Links with query strings
    for link in parser.links[:500]:
        href = link["href"]
        parsed = urlparse(href)
        if not parsed.query:
            continue
        for pk in link.get("query_keys") or []:
            add_row(href, pk, "html_a_href")
            if pk.lower() in SUSPICIOUS_LFI_PARAMS:
                from urllib.parse import urlencode as _ue, parse_qs as _pqs
                parsed = urlparse(href)
                qs = _pqs(parsed.query, keep_blank_values=True)
                if pk in qs:
                    new_q = dict(qs)
                    new_q[pk] = ["FUZZ"]
                    flat = []
                    for k, vals in new_q.items():
                        for v in vals:
                            flat.append((k, v))
                    fuzz_href = urlunparse(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            "",
                            _ue(flat),
                            "",
                        )
                    )
                    key = fuzz_href.lower()
                    if key not in seen_lfi_urls:
                        seen_lfi_urls.add(key)
                        lfi_fuzz_targets.append(
                            {
                                "ffuf_lfi_url": fuzz_href,
                                "param": pk,
                                "endpoint": href.split("?")[0],
                                "source": "html_a_href",
                            }
                        )

    return {
        "forms": compact_forms[:30],
        "links_with_query_sample": [
            {"href": x["href"], "query_keys": x["query_keys"]}
            for x in parser.links
            if x.get("query_keys")
        ][:40],
        "js_url_literals": js_literals[:25],
        "cms_hints": cms_hints[:15],
        "suspicious_param_rows": suspicious_rows,
        "lfi_fuzz_targets": lfi_fuzz_targets,
    }


def merge_surface_suspicious(
    surface: dict,
    existing: list[dict],
    merge_seen: set[tuple[str, str]],
) -> list[dict]:
    """Merge surface-derived rows into existing suspicious_params list (deduped)."""
    out = list(existing)
    for row in surface.get("suspicious_param_rows") or []:
        u = row.get("url") or ""
        p = (row.get("param") or "").lower()
        if not u or not p:
            continue
        parsed = urlparse(u)
        key = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower(), p)
        if key in merge_seen:
            continue
        merge_seen.add(key)
        out.append(
            {
                "url": row["url"],
                "param": row["param"],
                "lfi_candidate": row.get("lfi_candidate", False),
                "categories": row.get("categories") or classify_param_categories(row["param"]),
                "source": row.get("source", "html_surface"),
                "suggest_ffuf_lfi": row.get("suggest_ffuf_lfi", False),
            }
        )
    return out


def compact_surface_for_finding(surface: dict) -> dict:
    """Trim nested lists for findings.jsonl."""
    return {
        "forms": surface.get("forms") or [],
        "links_with_query_sample": surface.get("links_with_query_sample") or [],
        "js_url_literals": surface.get("js_url_literals") or [],
        "cms_hints": surface.get("cms_hints") or [],
        "lfi_fuzz_targets": (surface.get("lfi_fuzz_targets") or [])[:25],
    }
