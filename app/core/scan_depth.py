"""Shared rules for --depth vs directory fuzz (ffuf_dirs) base URLs."""

from urllib.parse import urlparse


def ffuf_dirs_extra_depth(target: str, scan_url: str) -> int:
    """
    Path segments deeper than the initial --url path for this scan base.

    - Same host as target: extra = len(scan path segments) - len(target path segments).
    - Different host (e.g. discovered vhost): extra = full path segment count from /.

    Returns 999 if scan_url is not under target path on the same host (invalid scope).
    """
    t = urlparse(target.rstrip("/") + "/")
    u = urlparse(scan_url.rstrip("/") + "/")
    u_parts = [p for p in u.path.strip("/").split("/") if p]
    if (u.hostname or "").lower() != (t.hostname or "").lower():
        return len(u_parts)
    t_parts = [p for p in t.path.strip("/").split("/") if p]
    if len(u_parts) < len(t_parts) or u_parts[: len(t_parts)] != t_parts:
        return 999
    return len(u_parts) - len(t_parts)


def ffuf_dirs_depth_allows(target: str, scan_url: str, depth: object) -> bool:
    """True iff directory fuzz on scan_url is allowed for this depth setting."""
    if depth is None:
        return True
    if not isinstance(depth, int) or depth < 0:
        return True
    extra = ffuf_dirs_extra_depth(target, scan_url)
    if extra >= 999:
        return False
    return extra <= depth
