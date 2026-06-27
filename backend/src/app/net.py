"""Client-IP extraction that honours a configured number of trusted proxies.

Used for login/enroll rate-limiting and audit ``source_ip``. ``X-Forwarded-For``
is client-controllable, so we trust only the rightmost ``trusted_proxy_hops``
entries (each appended by a reverse proxy we operate) and ignore anything the
client may have prepended.
"""

from __future__ import annotations

from fastapi import Request

from app.config import get_settings


def client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limiting and audit.

    Returns the entry the outermost trusted proxy reported — ``xff[-hops]`` — so a
    client can't spoof its IP by prepending fake ``X-Forwarded-For`` values. With
    0 hops, or when the header carries fewer entries than configured, falls back
    to the direct peer.
    """
    hops = get_settings().trusted_proxy_hops
    if hops > 0:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            parts = [p.strip() for p in fwd.split(",") if p.strip()]
            if len(parts) >= hops:
                return parts[-hops]
    return request.client.host if request.client else "unknown"
