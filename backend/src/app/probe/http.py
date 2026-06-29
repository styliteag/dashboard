"""HTTP reachability probe (httpx — already a dependency)."""

from __future__ import annotations

import httpx


def http_ok(status: int) -> bool:
    """``< 400`` means the box answered — a 302 login redirect counts as reachable."""
    return status < 400


async def http_probe(url: str, timeout: float = 5.0) -> tuple[bool, int | None]:
    """``(up, status)`` for a single GET.

    TLS verification is OFF — firewall management UIs use self-signed certs — and
    redirects are NOT followed: the first response (even a 302) already proves the
    box is up, and following the redirect could wander off to an unrelated host.
    """
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=timeout
        ) as client:
            resp = await client.get(url)
        return http_ok(resp.status_code), resp.status_code
    except httpx.HTTPError:
        return False, None
