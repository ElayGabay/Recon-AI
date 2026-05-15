"""
Resolve lines from a user-supplied directory list file into ffuf base URLs.

Each line becomes exactly one fuzz base: ``<base>/FUZZ`` — never a parent path.
"""

from pathlib import Path
from urllib.parse import urlunparse, urlparse

from app.core.scope_guard import ScopeGuard


def _collapse_path(path: str) -> str:
    """Normalize to /a/b with no trailing slash, or '' for site root path."""
    path = (path or "").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    parts: list[str] = []
    for seg in path.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    if not parts:
        return ""
    return "/" + "/".join(parts)


def line_to_fuzz_base_url(line: str, scope_url: str, guard: ScopeGuard) -> str | None:
    """
    One non-empty line → one base URL for ``run_ffuf_directory`` (…/FUZZ).

    Accepts:
    - Full URL: ``http://host/admin/login`` (query/fragment ignored)
    - Absolute path: ``/admin/users``, ``/robots/``
    - Relative segment: ``robots`` → ``/robots`` on the scope host
    """
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    raw = raw.split()[0]

    scope_norm = guard.normalize_target(scope_url)
    sp = urlparse(scope_norm)
    origin = f"{sp.scheme}://{sp.netloc}"

    if raw.startswith(("http://", "https://")):
        p = urlparse(raw)
        if not p.scheme or not p.netloc:
            return None
        path = _collapse_path(p.path or "/")
        path_part = path if path else "/"
        clean = urlunparse(
            (p.scheme.lower(), p.netloc.lower(), path_part, "", "", ""),
        )
        guard.require_allowed(clean)
        return clean.rstrip("/") if path else origin.rstrip("/")

    path = _collapse_path(raw)
    if path == "":
        base = origin.rstrip("/")
    else:
        base = (origin.rstrip("/") + path).rstrip("/")
    guard.require_allowed(base)
    return base


def load_directory_fuzz_targets(
    file_path: Path,
    scope_url: str,
    guard: ScopeGuard,
) -> list[str]:
    """
    Read ``file_path``; return unique bases in file order (case-insensitive dedupe).
    """
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    seen: set[str] = set()
    out: list[str] = []
    for line in text.splitlines():
        url = line_to_fuzz_base_url(line, scope_url, guard)
        if not url:
            continue
        key = url.rstrip("/").lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(url)
    return out
