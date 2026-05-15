"""Normalize optional --cookie CLI value for HTTP tools."""


def normalize_cookie_arg(cookie: str | None) -> str | None:
    """
    Return the Cookie header value (without the 'Cookie:' prefix), or None.

    Accepts, among others:
    - ``name=value`` (e.g. ``auth_token=SWNUDXHr6j29ZzrNJYFEaA``)
    - A bare opaque token (e.g. ``SWNUDXHr6j29ZzrNJYFEaA``) — sent as the header value as-is
    - ``Cookie: name=value`` — the ``Cookie:`` prefix is stripped
    - Outer matching ``'`` or ``"`` quotes (e.g. from shells) are stripped
    """
    if cookie is None:
        return None
    s = str(cookie).strip()
    if not s:
        return None

    # Strip outer matching quotes once or twice (e.g. --cookie 'auth_token=...' or "'a=1'")
    for _ in range(3):
        if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
            s = s[1:-1].strip()
        else:
            break

    if s.lower().startswith("cookie:"):
        s = s[7:].lstrip()

    return s or None
