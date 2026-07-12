"""Client-IP extraction that honours a configured number of trusted proxies.

Used for login/enroll rate-limiting, audit ``source_ip`` and the GeoIP
middleware. ``X-Forwarded-For`` is client-controllable, so we trust only the
rightmost ``trusted_proxy_hops`` entries (each appended by a reverse proxy we
operate) and ignore anything the client may have prepended.
"""

from __future__ import annotations

from fastapi import Request

from app.config import get_settings


def pick_client_ip(xff: str | None, peer: str | None) -> str:
    """Shared XFF/peer resolution for Request- and raw-ASGI callers.

    The GeoIP middleware runs below FastAPI and only has the ASGI scope — this
    single implementation keeps its notion of "client IP" byte-identical to
    ``client_ip`` (a divergence would let a spoofed header pass geo checks that
    audit would attribute to a different address).
    """
    hops = get_settings().trusted_proxy_hops
    if hops > 0 and xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops]
    return peer or "unknown"


def client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limiting and audit.

    Returns the entry the outermost trusted proxy reported — ``xff[-hops]`` — so a
    client can't spoof its IP by prepending fake ``X-Forwarded-For`` values. With
    0 hops, or when the header carries fewer entries than configured, falls back
    to the direct peer.
    """
    return pick_client_ip(
        request.headers.get("x-forwarded-for"),
        request.client.host if request.client else None,
    )
