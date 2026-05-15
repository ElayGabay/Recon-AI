from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
import re
import threading

import httpx

from app.core.report_manager import ReportManager
from app.core.output import log, print_probe_finding
from app.core.http_cookie import normalize_cookie_arg
from app.tools.html_surface import (
    MAX_HTML_EXCERPT,
    classify_param_categories,
    compact_surface_for_finding,
    discover_html_surface,
    merge_surface_suspicious,
)
from app.tools.param_discovery import (
    discover_and_analyze_parameters,
    emit_param_candidate_terminal,
)

# ── Session-wide terminal dedupe (same process, parallel probes) ─────────────
_PROBE_TERM_LOCK = threading.Lock()
_PROBE_TERM_SEEN: set[str] = set()


KEYWORDS = [
    "password",
    "passwd",
    "pwd",
    "username",
    "user",
    "email",
    "mail",
    "token",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "database",
    "db_password",
    "connection_string",
    "admin",
    "config",
]

SENSITIVE_KEYWORDS = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "db_password",
    "connection_string",
]

LOW_VALUE_TOKENS = [
    "csrf-token",
    "csrf-param",
    "authenticity_token",
    "_csrf",
]

STATIC_ASSET_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp"
}

STATIC_PATH_PARTS = {
    "/static/",
    "/assets/",
    "/images/",
    "/img/",
    "/css/",
    "/js/",
    "/fonts/",
}


def is_password_ui_boilerplate(line_lower: str) -> bool:
    """
    HTML / marketing copy that contains the word 'password' but is not a security finding.
    Pentesters care about real leaks, not login UX.
    """
    noise_markers = (
        "forgot-password",
        "forgot password",
        "forgot your password",
        "password recovery",
        "password reset",
        "reset password",
        "recover password",
        "change password",
        "we'll send you",
        "we will send you",
        "send you instructions",
        "instructions in email",
        "type=\"password\"",
        "type='password'",
        "<!-- password",
        "password field",
        "enter your password",
        "confirm password",
        "new password",
        "old password",
        "current password",
    )
    return any(m in line_lower for m in noise_markers)


def _probe_terminal_key(kind: str, url: str, detail: str) -> str:
    """Stable dedupe key for terminal (URL omitted for stack fingerprints)."""
    d = detail.strip().lower()
    if kind in {"version", "os"}:
        return f"{kind}:{d}"
    if kind == "email":
        return f"email:{d}"
    if kind in {"lfi", "param"}:
        return f"{kind}:{url.strip().lower()}:{d}"
    if kind == "secret":
        return f"secret:{d[:160]}"
    return f"{kind}:{url}:{d}"


def _probe_terminal_emit(kind: str, url: str, detail: str) -> None:
    """Print one probe line to the terminal once per unique finding (thread-safe)."""
    key = _probe_terminal_key(kind, url, detail)
    with _PROBE_TERM_LOCK:
        if key in _PROBE_TERM_SEEN:
            return
        _PROBE_TERM_SEEN.add(key)
    print_probe_finding(kind, url, detail)


def is_static_asset_line(line: str) -> bool:
    lower = line.lower()

    if any(part in lower for part in STATIC_PATH_PARTS):
        return True

    return any(ext in lower for ext in STATIC_ASSET_EXTENSIONS)


def is_low_value_keyword_match(keyword: str, line: str) -> bool:
    lower = line.lower()
    keyword = keyword.lower()

    if keyword in {"admin", "user"} and is_static_asset_line(lower):
        return True

    if keyword in {"email", "mail"}:
        return True

    if "forgot your password" in lower:
        return True

    if "forgot password" in lower and "<a " in lower:
        return True

    if "password reset" in lower and "<title>" in lower:
        return True

    if is_password_ui_boilerplate(lower):
        return True

    if 'type="password"' in lower:
        return True

    return False


# Parameters that are strong LFI / path-traversal candidates
SUSPICIOUS_LFI_PARAMS = {
    "file", "page", "path", "include", "template", "view",
    "inc", "document", "doc", "folder", "load", "read", "show",
    "fetch", "dir", "display", "resource", "src", "source",
    "require", "import", "module", "conf", "config",
}

# Broader set: injection / SSRF / open-redirect / info-leak candidates
SUSPICIOUS_ALL_PARAMS = SUSPICIOUS_LFI_PARAMS | {
    "search", "q", "query", "id", "user", "name", "cmd", "exec",
    "redirect", "url", "next", "return", "target", "goto", "dest",
    "ref", "action", "type", "kind", "mode", "lang", "locale",
}

# HTTP headers that reveal server-side software versions
VERSION_HEADERS = [
    "server",
    "x-powered-by",
    "x-generator",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-drupal-cache",
    "x-wp-total",
    "x-joomla-version",
]

EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
)

KEY_VALUE_REGEX = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|username|db_password|connection_string)\b\s*[:=]\s*[^\s\"']+"
)

LINK_REGEX = re.compile(
    r'''(?i)(?:href|src|action)\s*=\s*["']([^"']+)["']'''
)


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


def looks_like_directory(path_or_url: str) -> bool:
    path = urlparse(path_or_url).path

    if not path or path == "/":
        return False

    last_part = path.rstrip("/").split("/")[-1]

    if "." in last_part:
        return False

    return True


def extract_internal_paths(
    content: str,
    base_url: str,
    allowed_host: str,
    max_links: int = 100,
) -> list[dict]:
    discovered = []
    seen = set()

    for match in LINK_REGEX.finditer(content):
        raw_link = match.group(1)
        full_url = normalize_discovered_url(base_url, raw_link)

        if not full_url:
            continue

        if not is_internal_url(full_url, allowed_host):
            continue

        clean_url = full_url.split("#")[0]
        parsed = urlparse(clean_url)
        clean_path = parsed.path or "/"

        key = clean_url.rstrip("/")

        if key in seen:
            continue

        seen.add(key)

        discovered.append(
            {
                "url": clean_url,
                "path": clean_path,
                "is_directory_like": looks_like_directory(clean_path),
                "source": "html_link",
            }
        )

        if len(discovered) >= max_links:
            break

    return discovered


def mask_sensitive_value(text: str) -> str:
    """
    Keeps the indicator but masks long values so the report stays readable.
    """
    if len(text) <= 120:
        return text

    return text[:120] + "...[truncated]"


def extract_version_info(headers: dict) -> list[str]:
    """
    Pull software version strings out of HTTP response headers.
    Returns a list of human-readable strings like 'Server: nginx 1.18.0'.
    """
    versions = []
    for header in VERSION_HEADERS:
        val = headers.get(header, "").strip()
        if val:
            versions.append(f"{header}: {val}")
    return versions


def detect_os_hint(headers: dict, content: str) -> str:
    """
    Guess target OS from HTTP headers and page content.
    Returns 'linux', 'windows', or 'unknown'.
    """
    combined = (
        headers.get("server", "") + " " +
        headers.get("x-powered-by", "") + " " +
        headers.get("x-aspnet-version", "")
    ).lower()

    if any(w in combined for w in ("iis", "windows", "asp.net", "aspnetmvc")):
        return "windows"
    if any(w in combined for w in ("nginx", "apache", "ubuntu", "debian", "centos", "php")):
        return "linux"

    # Scan the first 4 KB of the page body for OS signals
    snippet = content[:4096].lower()
    if any(w in snippet for w in ("microsoft-iis", "windows server", "asp.net")):
        return "windows"
    if any(w in snippet for w in ("ubuntu", "debian", "centos", "linux", "/etc/passwd")):
        return "linux"

    return "unknown"


def _collect_url_params(url: str, suspicious: list, seen: set) -> None:
    """Add suspicious params found in a single URL to the results list."""
    parsed = urlparse(url)
    if not parsed.query:
        return
    for param in parse_qs(parsed.query, keep_blank_values=True):
        key = (parsed.scheme + "://" + (parsed.netloc or "") + parsed.path, param.lower())
        if key in seen:
            continue
        seen.add(key)
        suspicious.append({
            "url": url,
            "param": param,
            "lfi_candidate": param.lower() in SUSPICIOUS_LFI_PARAMS,
            "categories": classify_param_categories(param),
        })


def extract_suspicious_params(url: str, content: str, base_url: str, allowed_host: str) -> list[dict]:
    """
    Find URLs with suspicious query parameters from:
      1. The URL being probed itself
      2. All <a href>, <form action>, <img src> links inside the page
    Returns a list of dicts with url, param, lfi_candidate.
    """
    suspicious: list[dict] = []
    seen: set = set()

    _collect_url_params(url, suspicious, seen)

    for match in re.finditer(r'(?i)(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', content):
        raw = match.group(1)
        full = normalize_discovered_url(base_url, raw)
        if not full:
            continue
        if not is_internal_url(full, allowed_host):
            continue
        _collect_url_params(full, suspicious, seen)

    # Only keep params that are actually suspicious (not e.g. ?lang= or ?v=)
    return [s for s in suspicious if s["param"].lower() in SUSPICIOUS_ALL_PARAMS]


def _looks_like_html(content_type: str, content: str) -> bool:
    ct = (content_type or "").lower()
    if "html" in ct or "xml" in ct:
        return True
    head = (content[:12000] or "").lower()
    return any(
        marker in head
        for marker in (
            "<html",
            "<!doctype html",
            "<form",
            "<body",
            "<head",
        )
    )


def extract_interesting_lines(content: str, max_lines: int = 30) -> list[dict]:
    matches = []
    seen = set()

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):
        clean_line = line.strip()

        if not clean_line:
            continue

        lower_line = clean_line.lower()

        if is_password_ui_boilerplate(lower_line):
            continue

        for keyword in KEYWORDS:
            if keyword.lower() in lower_line:
                if is_low_value_keyword_match(keyword, clean_line):
                    continue

                if keyword == "token" and any(low in lower_line for low in LOW_VALUE_TOKENS):
                    match_type = "low_value_web_token"
                elif keyword in SENSITIVE_KEYWORDS:
                    match_type = "possible_secret_or_credential"
                elif keyword in {"email", "mail"}:
                    match_type = "email_indicator"
                else:
                    match_type = "keyword"

                key = (match_type, keyword, clean_line[:150])

                if key not in seen:
                    seen.add(key)
                    matches.append(
                        {
                            "type": match_type,
                            "keyword": keyword,
                            "line_number": line_number,
                            "preview": mask_sensitive_value(clean_line),
                        }
                    )

        for email in EMAIL_REGEX.findall(clean_line):
            key = ("email", email)

            if key not in seen:
                seen.add(key)
                matches.append(
                    {
                        "type": "email",
                        "keyword": "email",
                        "line_number": line_number,
                        "preview": email,
                    }
                )

        for key_value in KEY_VALUE_REGEX.finditer(clean_line):
            keyword = key_value.group(1)
            lower_keyword = keyword.lower()

            if is_password_ui_boilerplate(lower_line):
                continue

            if lower_keyword in {"token"} and any(low in lower_line for low in LOW_VALUE_TOKENS):
                match_type = "low_value_web_token"
            else:
                match_type = "possible_secret_or_credential"

            key = (match_type, line_number, clean_line[:150])

            if key not in seen:
                seen.add(key)
                matches.append(
                    {
                        "type": match_type,
                        "keyword": keyword,
                        "line_number": line_number,
                        "preview": mask_sensitive_value(clean_line),
                    }
                )

        if len(matches) >= max_lines:
            break

    return matches


def append_content_probe_to_report(report_path: Path, result: dict) -> None:
    manager = ReportManager(report_path.parent)

    severity = "info"
    title = "Content probe result"

    for match in result.get("matches", []):
        preview = (match.get("preview") or "").lower()
        keyword = (match.get("keyword") or "").lower()

        if 'type="password"' in preview:
            continue

        if "forgot your password" in preview:
            continue

        if "password reset" in preview and "<title>" in preview:
            continue

        if "/static/" in preview or "/assets/" in preview:
            continue

        if match.get("type") == "possible_secret_or_credential":
            severity = "high"
            title = f"Possible exposed {keyword or 'secret'} indicator"
            break

    manager.add_finding(
        {
            "type": "content_probe",
            "severity": severity,
            "title": title,
            "url": result.get("url"),
            "status": result.get("status_code"),
            "content_length": result.get("content_length"),
            "content_type": result.get("content_type"),
            "matches": result.get("matches", []),
            "discovered_paths": result.get("discovered_paths", []),
            "suspicious_params": result.get("suspicious_params", []),
            "html_surface": result.get("html_surface"),
            "html_excerpt": result.get("html_excerpt"),
            "lfi_fuzz_targets": result.get("lfi_fuzz_targets", []),
            "param_candidates": result.get("param_candidates", []),
        }
    )


def content_probe(
    url: str,
    allowed_host: str | None = None,
    report_path: Path | None = None,
    timeout_seconds: float = 8.0,
    max_response_bytes: int = 500_000,
    cookie: str | None = None,
) -> dict:
    if report_path is None:
        report_path = Path("app") / "reports" / "REPORT.txt"

    log(f"content_probe: {url}")

    if allowed_host is None:
        allowed_host = urlparse(url).hostname or ""

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; AI-Fuzzer-Agent/1.0)",
        }
        cookie_val = normalize_cookie_arg(cookie)
        if cookie_val:
            headers["Cookie"] = cookie_val

        response = httpx.get(
            url,
            follow_redirects=True,
            timeout=timeout_seconds,
            headers=headers,
        )

        content_bytes = response.content[:max_response_bytes]
        try:
            content = content_bytes.decode(response.encoding or "utf-8", errors="ignore")
        except Exception:
            content = content_bytes.decode("utf-8", errors="ignore")

        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # ── Version / OS detection ───────────────────────────────────────────
        versions       = extract_version_info(headers_lower)
        os_hint        = detect_os_hint(headers_lower, content)
        sus_params     = extract_suspicious_params(url, content, url, allowed_host)
        matches        = extract_interesting_lines(content)
        discovered_paths = extract_internal_paths(
            content=content, base_url=url, allowed_host=allowed_host,
        )

        merge_seen: set[tuple[str, str]] = set()
        for sp in sus_params:
            parsed = urlparse(sp["url"])
            merge_seen.add(
                (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower(),
                    (sp["param"] or "").lower(),
                )
            )

        html_surface_compact = None
        html_excerpt: str | None = None
        param_candidates: list[dict] = []
        lfi_from_discovery: list[dict] = []
        ct_raw = headers_lower.get("content-type", "")
        if _looks_like_html(ct_raw, content):
            surface = discover_html_surface(content, url, allowed_host)
            sus_params = merge_surface_suspicious(surface, sus_params, merge_seen)
            html_surface_compact = compact_surface_for_finding(surface)
            html_excerpt = content[:MAX_HTML_EXCERPT]

            discovery = discover_and_analyze_parameters(
                content,
                url,
                allowed_host,
                observed_url=url,
                cookie=cookie,
                run_response_tests=True,
                max_response_tests=6,
            )
            param_candidates = discovery.get("param_candidates") or []
            lfi_from_discovery = discovery.get("lfi_fuzz_targets") or []
            if html_surface_compact is not None:
                html_surface_compact["param_candidates"] = param_candidates[:20]
                html_surface_compact["lfi_fuzz_targets"] = lfi_from_discovery[:15]

        # ── Terminal output (deduped, noise-filtered) ────────────────────────
        for v in versions:
            _probe_terminal_emit("version", url, v)

        if os_hint != "unknown":
            _probe_terminal_emit("os", url, f"OS hint: {os_hint}")

        emit_param_candidate_terminal(param_candidates, url)

        for sp in sus_params:
            if any(
                pc.get("parameter", "").lower() == (sp.get("param") or "").lower()
                and pc.get("endpoint", "").split("?")[0]
                in (sp.get("url") or "").split("?")[0]
                for pc in param_candidates
            ):
                continue
            kind = "lfi" if sp["lfi_candidate"] else "param"
            cats = sp.get("categories")
            suffix = f"  [{','.join(cats)}]" if cats else ""
            _probe_terminal_emit(kind, sp["url"], f"?{sp['param']}={suffix}")

        for target in lfi_from_discovery:
            ffuf_url = target.get("ffuf_lfi_url", "")
            param = target.get("param", "")
            if ffuf_url:
                _probe_terminal_emit(
                    "lfi", ffuf_url, f"ffuf_lfi [{target.get('confidence', '?')}] ?{param}=FUZZ"
                )

        seen_emails: set = set()
        for m in matches:
            if m["type"] == "email" and m["preview"] not in seen_emails:
                seen_emails.add(m["preview"])
                _probe_terminal_emit("email", url, m["preview"])
            elif m["type"] in ("possible_secret_or_credential",):
                pv = m["preview"][:120]
                if is_password_ui_boilerplate(pv.lower()):
                    continue
                _probe_terminal_emit("secret", url, pv)

        # ── Persist to report / findings.jsonl ──────────────────────────────
        result = {
            "tool": "content_probe",
            "url": url,
            "status_code": response.status_code,
            "content_length": len(response.content),
            "content_type": headers_lower.get("content-type", ""),
            "versions": versions,
            "os_hint": os_hint,
            "suspicious_params": sus_params,
            "matches": matches,
            "discovered_paths": discovered_paths,
            "html_surface": html_surface_compact,
            "html_excerpt": html_excerpt,
            "lfi_fuzz_targets": lfi_from_discovery,
            "param_candidates": param_candidates,
        }

        if (
            matches or sus_params or versions or html_surface_compact
            or html_excerpt or param_candidates or lfi_from_discovery
        ):
            append_content_probe_to_report(report_path, result)

        return result

    except httpx.RequestError as exc:
        log(f"content_probe error: {exc}")
        return {
            "tool": "content_probe",
            "url": url,
            "error": str(exc),
            "versions": [],
            "os_hint": "unknown",
            "suspicious_params": [],
            "matches": [],
            "discovered_paths": [],
            "html_surface": None,
            "html_excerpt": None,
            "lfi_fuzz_targets": [],
            "param_candidates": [],
        }