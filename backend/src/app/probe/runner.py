"""Combine ICMP + HTTP into one reachability result for an instance's ping target.

A ``ping_url`` may be a bare host/IP (ICMP only) or a full http(s) URL (ICMP to
its host *and* an HTTP GET). Each axis is independent: a box can answer ICMP while
its web service is down, which is itself a useful, distinct signal.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse

from app.probe import http as http_mod
from app.probe import icmp as icmp_mod


@dataclass(frozen=True)
class ProbeResult:
    """One reachability measurement. ``None`` on an axis means "not probed"."""

    icmp_up: bool | None = None
    http_up: bool | None = None
    rtt_ms: float | None = None
    http_status: int | None = None

    @property
    def probed(self) -> bool:
        """True when at least one axis actually ran."""
        return self.icmp_up is not None or self.http_up is not None


def target_host(ping_url: str | None) -> str | None:
    """Host/IP to ICMP. A URL → its hostname; a bare ``host[:port]`` → ``host``."""
    v = (ping_url or "").strip()
    if not v:
        return None
    if "://" in v:
        return urlparse(v).hostname
    # Bare host or host:port (IPv4/hostname). Strip a single :port; leave IPv6 alone.
    if v.count(":") == 1:
        return v.split(":", 1)[0]
    return v


def http_target(ping_url: str | None) -> str | None:
    """Full URL to GET, or None when the target isn't an http(s) URL."""
    v = (ping_url or "").strip()
    if "://" not in v:
        return None
    return v if urlparse(v).scheme in ("http", "https") else None


async def run_probe(
    ping_url: str | None, *, icmp_timeout: float = 1.0, http_timeout: float = 5.0
) -> ProbeResult:
    """Probe a ping target. Returns an all-None result when there's nothing to probe."""
    host = target_host(ping_url)
    url = http_target(ping_url)
    if host is None and url is None:
        return ProbeResult()

    # ICMP is a blocking socket → run it off the event loop.
    rtt = await asyncio.to_thread(icmp_mod.ping, host, icmp_timeout) if host else None
    http_up, status = await http_mod.http_probe(url, timeout=http_timeout) if url else (None, None)
    return ProbeResult(
        icmp_up=(rtt is not None) if host else None,
        http_up=http_up,
        rtt_ms=rtt,
        http_status=status,
    )
