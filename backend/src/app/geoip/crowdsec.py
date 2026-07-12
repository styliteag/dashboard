"""CrowdSec bad-actor blocklist (DR-G8) — stream-mode bouncer, process cache.

A scheduler job pulls ban decisions from the CrowdSec LAPI
(``/v1/decisions/stream``): the first call after process start fetches the
full set (``startup=true``), later calls only deltas. The middleware checks
IPs against the cached set — never live HTTP in the request path. A LAPI
outage keeps the last known bans (stale beats empty: dropping the list on a
hiccup would un-ban every attacker at once); the staleness is visible in the
status endpoint.

Single IPs (the overwhelming majority of community-blocklist entries) live in
an O(1) set; genuine ranges in a small tuple that is scanned linearly.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import httpx
import structlog

from app.config import get_settings

log = structlog.get_logger("app.geoip")

_SYNC_TIMEOUT = 15.0

# Process-local state (single worker by design).
_banned_ips: set[str] = set()
_banned_ranges: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
_startup_done = False
_last: dict = {"at": None, "ok": None, "detail": "never synced"}


def active() -> bool:
    """True when the blocklist check should run at all."""
    settings = get_settings()
    return settings.crowdsec_enabled and bool(settings.crowdsec_api_key)


def banned_count() -> int:
    return len(_banned_ips) + len(_banned_ranges)


def is_banned(ip: str) -> bool:
    """O(1) for single-IP bans, linear over the (few) range bans."""
    if ip in _banned_ips:
        return True
    if not _banned_ranges:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _banned_ranges.values() if addr.version == net.version)


def status() -> dict:
    return {
        "enabled": get_settings().crowdsec_enabled,
        "configured": active(),
        "banned_count": banned_count(),
        **_last,
    }


def _normalize(value: str) -> tuple[str, str] | None:
    """Decision value → ('ip', canonical) or ('range', canonical); None = junk."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    if net.num_addresses == 1:
        return "ip", str(net.network_address)
    return "range", str(net)


def apply_decisions(new: list[dict], deleted: list[dict]) -> None:
    """Fold one stream delta into the cache (pure state transition, testable)."""
    for decision, removing in ((deleted, True), (new, False)):
        for d in decision:
            if (d.get("type") or "ban") != "ban":
                continue
            norm = _normalize(str(d.get("value", "")))
            if norm is None:
                continue
            kind, canonical = norm
            if removing:
                if kind == "ip":
                    _banned_ips.discard(canonical)
                else:
                    _banned_ranges.pop(canonical, None)
            elif kind == "ip":
                _banned_ips.add(canonical)
            else:
                _banned_ranges[canonical] = ipaddress.ip_network(canonical)


async def sync() -> None:
    """Scheduler entry point: pull the next stream delta (full set on first run)."""
    global _startup_done
    if not active():
        return
    settings = get_settings()
    url = settings.crowdsec_lapi_url.rstrip("/") + "/v1/decisions/stream"
    try:
        async with httpx.AsyncClient(timeout=_SYNC_TIMEOUT) as client:
            resp = await client.get(
                url,
                params={"startup": "true" if not _startup_done else "false"},
                headers={"X-Api-Key": settings.crowdsec_api_key},
            )
        if resp.status_code != 200:
            _finish(ok=False, detail=f"LAPI HTTP {resp.status_code}")
            return
        data = resp.json() or {}
    except (httpx.HTTPError, ValueError) as exc:
        # Keep the last known bans — stale beats empty (see module docstring).
        _finish(ok=False, detail=f"{exc.__class__.__name__}: {exc}")
        return
    apply_decisions(data.get("new") or [], data.get("deleted") or [])
    _startup_done = True
    _finish(ok=True, detail=f"{banned_count()} active bans")


def _finish(ok: bool, detail: str) -> None:
    _last.update(at=datetime.now(UTC).isoformat(), ok=ok, detail=detail)
    if ok:
        log.debug("geoip.crowdsec_sync", detail=detail)
    else:
        log.warning("geoip.crowdsec_sync_failed", detail=detail)
