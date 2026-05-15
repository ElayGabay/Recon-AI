"""
Evidence-first parameter discovery with confidence scoring and response comparison.

Pipeline:
  1. Collect parameters only from HTML forms, links, JavaScript, and the probed URL.
  2. Optionally mine common names (marked heuristic / low — not reported by default).
  3. Compare baseline vs variant responses to reduce false positives.
  4. Emit structured param_candidates for the brain and orchestrator.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlparse, urljoin, urlunparse

import httpx

from app.core.http_cookie import normalize_cookie_arg
from app.core.output import log, print_probe_finding

# Names that strongly suggest path / file inclusion when found in real HTML/URLs
LFI_STRONG_NAMES = {
    "file", "page", "path", "include", "template", "view", "inc", "document", "doc",
    "folder", "load", "read", "dir", "fetch", "display", "resource", "src", "source",
    "require", "import", "module", "conf", "config", "show",
}

GENERIC_INTERESTING_NAMES = {
    "q", "search", "query", "id", "category", "type", "lang", "redirect", "url",
    "name", "user", "action", "mode", "sort", "filter", "term", "keyword",
}

# Optional mining — never reported unless response proves behavior
MINING_PARAM_NAMES = (
    "file", "page", "path", "id", "lang", "view", "template", "redirect", "url",
    "include", "load", "dir",
)

PROBE_MARKER = "__recon_probe_diff__"

_JS_URL_IN_CODE = re.compile(
    r"""(?i)(?:fetch|axios\.get|axios\.post|\$\.(?:get|ajax)|open\s*\(\s*['"]GET['"])\s*\(\s*['"]([^'"]+)['"]"""
)
_JS_HREF_QUERY = re.compile(
    r"""(?i)['"](/[^'"]*\?[^'"]+)['"]"""
)

_TITLE_RE = re.compile(r"(?is)<title[^>]*>([^<]+)</title>")
_LFI_ERROR_MARKERS = (
    "no such file", "failed to open stream", "include(", "require(",
    "warning: include", "open_basedir", "/etc/passwd", "root:", "php://",
)


def _strip_fragment(u: str) -> str:
    return u.split("#", 1)[0]


def is_internal_url(url: str, allowed_host: str) -> bool:
    parsed = urlparse(url)
    if not parsed.hostname:
        return True
    h = parsed.hostname.lower()
    ah = allowed_host.lower()
    return h == ah or h.endswith("." + ah)


def normalize_discovered_url(base_url: str, raw_link: str) -> str | None:
    raw = (raw_link or "").strip()
    if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    return urljoin(base_url, raw)


def build_query_url(base: str, params: dict[str, str]) -> str:
    parsed = urlparse(base)
    q = urlencode(list(params.items()))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", q, ""))


def build_ffuf_lfi_url(action_url: str, field_names: list[str], fuzz_param: str) -> str:
    names = [n for n in field_names if n]
    if fuzz_param not in names:
        names.append(fuzz_param)
    params = {n: ("FUZZ" if n == fuzz_param else "test") for n in names}
    return build_query_url(action_url, params)


def _source_label(discovery_type: str) -> str:
    return {
        "confirmed_from_html_form": "HTML form",
        "confirmed_from_html_link": "HTML link",
        "confirmed_from_javascript": "JavaScript",
        "confirmed_from_observed_url": "observed URL",
        "heuristic_guess": "guessed_parameter",
    }.get(discovery_type, discovery_type)


def _name_tier(param: str) -> str:
    pl = param.lower().strip()
    if not pl:
        return "unknown"
    if pl in LFI_STRONG_NAMES:
        return "lfi_strong"
    if pl in GENERIC_INTERESTING_NAMES:
        return "generic"
    if len(pl) == 1 and pl.isalpha():
        return "single_letter"
    if pl in {"test", "value", "data", "input", "x", "y", "z", "a", "b"}:
        return "weak_guess"
    return "other"


def assign_name_confidence(param: str, discovery_type: str) -> str:
    """Return high | medium | low based on evidence source + parameter name."""
    if discovery_type == "heuristic_guess":
        return "low"

    tier = _name_tier(param)
    if tier == "lfi_strong":
        return "high"
    if tier == "single_letter" or tier == "weak_guess":
        return "low"
    if tier == "generic":
        return "medium"
    if discovery_type.startswith("confirmed_"):
        return "medium"
    return "low"


def _suspected_tests(param: str, discovery_type: str, tier: str) -> list[str]:
    tests: list[str] = []
    pl = param.lower()
    if tier == "lfi_strong" or pl in LFI_STRONG_NAMES:
        tests.append("lfi_candidate")
    if pl in {"q", "search", "query", "s", "keyword", "term"}:
        tests.extend(["search_behavior_analysis", "content_discovery_candidate"])
    if pl in {"id", "user", "uid", "order", "sort"}:
        tests.append("sqli_candidate")
    if pl in {"redirect", "url", "next", "return", "goto", "dest", "target"}:
        tests.append("open_redirect_candidate")
    if not tests and discovery_type.startswith("confirmed_"):
        tests.append("injection_surface_candidate")
    return list(dict.fromkeys(tests))


def _not_reported_as(confidence: str, tier: str, reflection_only: bool) -> list[str]:
    blocked = ["confirmed_lfi", "confirmed_sqli", "confirmed_vulnerability"]
    if confidence == "low":
        return blocked + ["candidate_in_report"]
    if reflection_only or tier == "generic":
        return blocked + ["confirmed_lfi"]
    if tier != "lfi_strong":
        return blocked + ["confirmed_lfi"]
    return blocked


def build_param_candidate(
    *,
    endpoint: str,
    method: str,
    parameter: str,
    discovery_type: str,
    field_names: list[str] | None = None,
    example_url: str = "",
    response_analysis: dict | None = None,
) -> dict:
    tier = _name_tier(parameter)
    confidence = assign_name_confidence(parameter, discovery_type)
    ra = response_analysis or {}
    reflection_only = bool(ra.get("reflection_only"))
    meaningful_diff = bool(ra.get("meaningful_difference"))

    if reflection_only and confidence == "high" and tier != "lfi_strong":
        confidence = "medium"

    if discovery_type == "heuristic_guess" and not meaningful_diff:
        vulnerability_status = "not_reported"
    elif reflection_only and tier == "generic":
        vulnerability_status = "candidate_only"
    elif confidence == "high" and (tier == "lfi_strong" or meaningful_diff):
        vulnerability_status = "candidate_high_priority"
    elif confidence in {"high", "medium"}:
        vulnerability_status = "candidate_only"
    else:
        vulnerability_status = "not_reported"

    # ffuf_lfi only for strong evidence — not every form field
    schedule_ffuf_lfi = (
        vulnerability_status != "not_reported"
        and not reflection_only
        and (
            (confidence == "high" and tier == "lfi_strong")
            or (meaningful_diff and ra.get("lfi_error_signals"))
        )
    )

    tests = _suspected_tests(parameter, discovery_type, tier)
    reason_parts = [
        f"Parameter '{parameter}' from {_source_label(discovery_type)}.",
    ]
    if reflection_only:
        reason_parts.append(
            "Response changes appear to be input reflection only (same layout/messages)."
        )
    elif meaningful_diff:
        reason_parts.append("Modified values produced a meaningful response difference.")
    else:
        reason_parts.append("No response comparison yet or responses matched baseline.")
    if tier == "generic":
        reason_parts.append(
            "Generic name — treat as search/input candidate, not confirmed LFI."
        )

    cand = {
        "endpoint": endpoint,
        "method": method,
        "parameter": parameter,
        "source": _source_label(discovery_type),
        "discovery_type": discovery_type,
        "confidence": confidence,
        "vulnerability_status": vulnerability_status,
        "suspected_tests": tests,
        "not_reported_as": _not_reported_as(confidence, tier, reflection_only),
        "reason": " ".join(reason_parts),
        "example_url": example_url,
        "schedule_ffuf_lfi": schedule_ffuf_lfi,
        "report_in_findings": vulnerability_status != "not_reported",
    }
    if field_names:
        cand["ffuf_lfi_url"] = build_ffuf_lfi_url(endpoint, field_names, parameter)
    elif "?" in example_url:
        cand["ffuf_lfi_url"] = build_ffuf_lfi_url(
            example_url.split("?")[0], [parameter], parameter
        )
    if response_analysis:
        cand["response_analysis"] = response_analysis
    return cand


class _FormParser(HTMLParser):
    def __init__(self, page_url: str, allowed_host: str):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.allowed_host = allowed_host
        self.forms: list[dict] = []
        self.links: list[dict] = []
        self._form: dict | None = None

    def _resolve(self, raw: str | None) -> str | None:
        raw = (raw or "").strip()
        if not raw:
            return _strip_fragment(self.page_url)
        if raw.lower().startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        full = normalize_discovered_url(self.page_url, raw)
        if not full or not is_internal_url(full, self.allowed_host):
            return None
        return _strip_fragment(full)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "form":
            action = self._resolve(a.get("action")) or _strip_fragment(self.page_url)
            self._form = {
                "action_abs": action,
                "method": (a.get("method") or "get").upper(),
                "fields": [],
            }
        elif t == "input" and self._form is not None:
            name = (a.get("name") or "").strip()
            itype = (a.get("type") or "text").lower()
            if name and itype not in {"submit", "button", "image", "reset"}:
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
            if parsed.query:
                self.links.append({"href": full, "query_keys": list(parse_qs(parsed.query).keys())})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def extract_js_url_params(html: str, page_url: str, allowed_host: str) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    chunk = html[:400_000]
    for rx in (_JS_URL_IN_CODE, _JS_HREF_QUERY):
        for m in rx.finditer(chunk):
            raw = m.group(1).strip()
            full = normalize_discovered_url(page_url, raw)
            if not full or not is_internal_url(full, allowed_host):
                continue
            parsed = urlparse(full)
            if not parsed.query:
                continue
            for pk in parse_qs(parsed.query, keep_blank_values=True):
                key = (parsed.path.lower(), pk.lower())
                if key in seen:
                    continue
                seen.add(key)
                found.append({"href": full, "param": pk, "endpoint": full.split("?")[0]})
    return found


def discover_confirmed_parameters(
    html: str,
    page_url: str,
    allowed_host: str,
    *,
    observed_url: str | None = None,
    max_html_bytes: int = 600_000,
) -> list[dict]:
    """Collect parameter candidates only from real page evidence (no random guessing)."""
    allowed_host = allowed_host or (urlparse(page_url).hostname or "")
    snippet = html[:max_html_bytes]
    parser = _FormParser(page_url, allowed_host)
    try:
        parser.feed(snippet)
        parser.close()
    except Exception:
        pass
    if parser._form is not None:
        parser.forms.append(parser._form)

    candidates: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add_candidate(c: dict) -> None:
        ep = urlparse(c.get("endpoint", ""))
        key = (f"{ep.scheme}://{ep.netloc}{ep.path}".lower(), c["parameter"].lower())
        if key in seen:
            return
        seen.add(key)
        candidates.append(c)

    for form in parser.forms:
        action = form["action_abs"]
        method = form["method"]
        names = [f["name"] for f in form["fields"] if f.get("name")]
        if method == "GET" and names:
            example = build_query_url(action, {n: "test" for n in names})
            for n in names:
                add_candidate(
                    build_param_candidate(
                        endpoint=action,
                        method="GET",
                        parameter=n,
                        discovery_type="confirmed_from_html_form",
                        field_names=names,
                        example_url=example,
                    )
                )

    for link in parser.links[:300]:
        for pk in link.get("query_keys") or []:
            add_candidate(
                build_param_candidate(
                    endpoint=link["href"].split("?")[0],
                    method="GET",
                    parameter=pk,
                    discovery_type="confirmed_from_html_link",
                    example_url=link["href"],
                )
            )

    for js in extract_js_url_params(snippet, page_url, allowed_host):
        add_candidate(
            build_param_candidate(
                endpoint=js["endpoint"],
                method="GET",
                parameter=js["param"],
                discovery_type="confirmed_from_javascript",
                example_url=js["href"],
            )
        )

    if observed_url:
        parsed = urlparse(observed_url)
        if parsed.query:
            for pk in parse_qs(parsed.query, keep_blank_values=True):
                add_candidate(
                    build_param_candidate(
                        endpoint=observed_url.split("?")[0],
                        method="GET",
                        parameter=pk,
                        discovery_type="confirmed_from_observed_url",
                        example_url=observed_url,
                    )
                )

    return candidates


def mine_guessed_parameters(endpoint: str, method: str = "GET") -> list[dict]:
    """Low-priority common names — internal only unless response proves behavior."""
    out = []
    for name in MINING_PARAM_NAMES:
        out.append(
            build_param_candidate(
                endpoint=endpoint,
                method=method,
                parameter=name,
                discovery_type="heuristic_guess",
                example_url=build_query_url(endpoint, {name: "test"}),
            )
        )
    return out


def fingerprint_response(
    status_code: int,
    content: str,
    headers: dict | None = None,
) -> dict:
    headers = headers or {}
    title_m = _TITLE_RE.search(content[:80_000])
    title = (title_m.group(1).strip() if title_m else "")[:200]
    words = len(re.findall(r"\w+", content[:100_000]))
    body_low = content[:50_000].lower()
    return {
        "status_code": status_code,
        "content_length": len(content),
        "word_count": words,
        "title": title,
        "location": headers.get("location", headers.get("Location", "")),
        "has_no_data_message": "no data found" in body_low,
        "lfi_error_signals": any(m in body_low for m in _LFI_ERROR_MARKERS),
    }


def _normalize_for_reflection(text: str, *values: str) -> str:
    out = text
    for v in values:
        if v and len(v) >= 1:
            out = out.replace(v, "{{VAL}}")
    return re.sub(r"\s+", " ", out)[:80_000]


def compare_response_variants(
    baseline: dict,
    variant_a: dict,
    variant_b: dict,
    *,
    value_a: str = "",
    value_b: str = "",
) -> dict:
    """Compare baseline vs two test values; detect reflection-only behavior."""
    fp0 = baseline.get("fingerprint") or {}
    fp1 = variant_a.get("fingerprint") or {}
    fp2 = variant_b.get("fingerprint") or {}

    def differs(a: dict, b: dict) -> bool:
        if a.get("status_code") != b.get("status_code"):
            return True
        if abs(a.get("content_length", 0) - b.get("content_length", 0)) > 80:
            return True
        if a.get("title") != b.get("title"):
            return True
        if a.get("location") != b.get("location"):
            return True
        if a.get("has_no_data_message") != b.get("has_no_data_message"):
            return True
        return False

    meaningful = differs(fp0, fp1) or differs(fp0, fp2) or differs(fp1, fp2)
    lfi_signals = fp1.get("lfi_error_signals") or fp2.get("lfi_error_signals")

    body0 = baseline.get("body", "")
    body1 = variant_a.get("body", "")
    body2 = variant_b.get("body", "")
    norm1 = _normalize_for_reflection(body1, value_a, value_b)
    norm2 = _normalize_for_reflection(body2, value_a, value_b)
    norm0 = _normalize_for_reflection(body0, value_a, value_b)
    reflection_only = False
    if meaningful and value_a and value_b:
        if norm1 == norm2 or (norm0 == norm1 and differs(fp0, fp1)):
            reflection_only = True
        if abs(len(norm1) - len(norm2)) < 40 and fp1.get("title") == fp2.get("title"):
            if fp1.get("has_no_data_message") and fp2.get("has_no_data_message"):
                reflection_only = True

    return {
        "meaningful_difference": meaningful and not reflection_only,
        "reflection_only": reflection_only,
        "lfi_error_signals": lfi_signals,
        "baseline_status": fp0.get("status_code"),
        "test_statuses": [fp1.get("status_code"), fp2.get("status_code")],
    }


def _fetch(
    client: httpx.Client,
    url: str,
    max_bytes: int,
) -> tuple[int, str, dict]:
    r = client.get(url, follow_redirects=True)
    body = r.content[:max_bytes].decode(errors="ignore")
    return r.status_code, body, {k.lower(): v for k, v in r.headers.items()}


def analyze_candidate_responses(
    candidate: dict,
    *,
    cookie: str | None = None,
    timeout: float = 8.0,
    max_bytes: int = 200_000,
) -> dict:
    """GET only: fetch baseline + two variants and attach response_analysis."""
    if candidate.get("method", "GET").upper() != "GET":
        return candidate

    endpoint = candidate["endpoint"]
    param = candidate["parameter"]
    names = [param]
    ex = candidate.get("example_url") or ""
    if "?" in ex:
        for k in parse_qs(urlparse(ex).query):
            if k != param and k not in names:
                names.append(k)

    url_base = build_query_url(endpoint, {n: "" for n in names})
    url_a = build_query_url(endpoint, {n: ("12" if n == param else "test") for n in names})
    url_b = build_query_url(
        endpoint, {n: (PROBE_MARKER if n == param else "test") for n in names}
    )

    headers = {"User-Agent": "Mozilla/5.0 (compatible; AI-Fuzzer-Agent/1.0)"}
    cv = normalize_cookie_arg(cookie)
    if cv:
        headers["Cookie"] = cv

    try:
        with httpx.Client(timeout=timeout, headers=headers) as client:
            s0, b0, h0 = _fetch(client, url_base, max_bytes)
            s1, b1, h1 = _fetch(client, url_a, max_bytes)
            s2, b2, h2 = _fetch(client, url_b, max_bytes)
    except httpx.RequestError as exc:
        log(f"[param-discovery] response test failed for {endpoint}?{param}=: {exc}")
        return candidate

    analysis = compare_response_variants(
        {
            "fingerprint": fingerprint_response(s0, b0, h0),
            "body": b0,
        },
        {"fingerprint": fingerprint_response(s1, b1, h1), "body": b1},
        {"fingerprint": fingerprint_response(s2, b2, h2), "body": b2},
        value_a="12",
        value_b=PROBE_MARKER,
    )
    updated = build_param_candidate(
        endpoint=endpoint,
        method="GET",
        parameter=param,
        discovery_type=candidate["discovery_type"],
        field_names=names if len(names) > 1 else [param],
        example_url=ex or url_a,
        response_analysis=analysis,
    )
    return updated


def discover_and_analyze_parameters(
    html: str,
    page_url: str,
    allowed_host: str,
    *,
    observed_url: str | None = None,
    cookie: str | None = None,
    run_response_tests: bool = True,
    max_response_tests: int = 6,
) -> dict:
    """
    Full pipeline for one probed page.
    Returns param_candidates (reportable), internal_guesses, lfi_fuzz_targets (schedulable only).
    """
    confirmed = discover_confirmed_parameters(
        html, page_url, allowed_host, observed_url=observed_url
    )

    tested: list[dict] = []
    for i, cand in enumerate(confirmed):
        if run_response_tests and i < max_response_tests and cand["method"] == "GET":
            tested.append(analyze_candidate_responses(cand, cookie=cookie))
        else:
            tested.append(cand)

    schedulable = [
        c for c in tested
        if c.get("schedule_ffuf_lfi") and c.get("ffuf_lfi_url")
    ]
    reportable = [c for c in tested if c.get("report_in_findings")]

    return {
        "param_candidates": reportable,
        "param_candidates_internal": tested,
        "lfi_fuzz_targets": [
            {
                "ffuf_lfi_url": c["ffuf_lfi_url"],
                "param": c["parameter"],
                "endpoint": c["endpoint"],
                "source": c["discovery_type"],
                "confidence": c["confidence"],
            }
            for c in schedulable
        ],
    }


def emit_param_candidate_terminal(candidates: list[dict], page_url: str) -> None:
    for c in candidates:
        if not c.get("report_in_findings"):
            continue
        conf = c.get("confidence", "?").upper()
        param = c.get("parameter", "")
        ep = c.get("endpoint", "")
        status = c.get("vulnerability_status", "")
        detail = f"[{conf}] ?{param}= — {status}"
        ra = c.get("response_analysis") or {}
        if ra.get("reflection_only"):
            detail += " (reflection only)"
        elif ra.get("meaningful_difference"):
            detail += " (response changed)"
        kind = "lfi" if c.get("schedule_ffuf_lfi") else "param"
        print_probe_finding(kind, ep or page_url, detail)
