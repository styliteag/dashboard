"""DynDNS whitelist resolution (DR-G4).

Hostnames in the whitelist are resolved in the background (A **and** AAAA);
the middleware only ever consults the last resolved set — never DNS in the
request path. Resolution failures KEEP the previous addresses: flapping DNS
must not lock a legitimate operator out; the staleness is visible per host in
the status endpoint.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog

log = structlog.get_logger("app.geoip")

_RESOLVE_TIMEOUT = 5.0  # per hostname; the job runs off the request path


@dataclass(frozen=True)
class HostState:
    ips: frozenset[str]
    resolved_at: datetime | None
    error: str | None


# hostname -> last known state. Process-local (single worker by design).
_state: dict[str, HostState] = {}


def resolved_ips() -> frozenset[str]:
    """Union of all last-known addresses across whitelist hostnames."""
    out: set[str] = set()
    for st in _state.values():
        out |= st.ips
    return frozenset(out)


def snapshot() -> list[dict]:
    """Per-host view for the superadmin status endpoint."""
    return [
        {
            "hostname": host,
            "ips": sorted(st.ips),
            "resolved_at": st.resolved_at.isoformat() if st.resolved_at else None,
            "error": st.error,
        }
        for host, st in sorted(_state.items())
    ]


async def _resolve_one(host: str) -> frozenset[str]:
    """All A+AAAA addresses of ``host`` (deduplicated, zone-ids stripped)."""
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
        timeout=_RESOLVE_TIMEOUT,
    )
    ips: set[str] = set()
    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        ips.add(addr.split("%", 1)[0])  # strip a v6 zone id, if any
    return frozenset(ips)


async def refresh(hostnames: tuple[str, ...]) -> None:
    """Re-resolve the given hostnames; drop state for entries no longer listed."""
    wanted = {h.lower() for h in hostnames}
    for gone in set(_state) - wanted:
        del _state[gone]
    now = datetime.now(UTC)
    for host in sorted(wanted):
        prev = _state.get(host)
        try:
            ips = await _resolve_one(host)
        except (TimeoutError, OSError, UnicodeError) as exc:
            # Keep the previous addresses — DR-G4: DNS failure must not lock out.
            _state[host] = HostState(
                ips=prev.ips if prev else frozenset(),
                resolved_at=prev.resolved_at if prev else None,
                error=str(exc) or exc.__class__.__name__,
            )
            log.warning("geoip.dyndns_resolve_failed", hostname=host, error=str(exc))
            continue
        if prev is None or ips != prev.ips:
            log.info("geoip.dyndns_resolved", hostname=host, ips=sorted(ips))
        _state[host] = HostState(ips=ips, resolved_at=now, error=None)


async def refresh_job() -> None:
    """Scheduler entry point: resolve whatever the current rules list."""
    from app.geoip.store import current_rules  # local import, avoids cycle

    hostnames = current_rules().hostnames
    if hostnames:
        await refresh(hostnames)
