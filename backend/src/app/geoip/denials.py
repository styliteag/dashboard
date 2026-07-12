"""Denial accounting for the GeoIP/CrowdSec gate — the operator's answer to
"who is knocking and from where?".

Process-local (single worker by design), intentionally bounded: three fixed
reason counters, a country counter (naturally capped at ~250 keys) and a ring
buffer of the last denials. Per-IP counters are deliberately absent — a
scanner cycling random source IPs must not be able to grow memory; individual
IPs are visible in the ring buffer. Counters reset on restart; long-term
series live in the Prometheus export (orbit_geoip_denied_total).
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import UTC, datetime

_RECENT_MAX = 200

_since: str | None = None  # ISO timestamp of the first recorded event
_by_reason: Counter[str] = Counter()
_by_country: Counter[str] = Counter()
_fail_open = 0  # allowed-because-mmdb-missing events (DR-G5 fail-open)
_recent: deque[dict] = deque(maxlen=_RECENT_MAX)


def record(ip: str | None, country: str | None, path: str, reason: str) -> None:
    global _since
    now = datetime.now(UTC).isoformat()
    if _since is None:
        _since = now
    _by_reason[reason] += 1
    _by_country[country or "??"] += 1
    _recent.appendleft(
        {"at": now, "ip": ip or "?", "country": country, "path": path, "reason": reason}
    )


def record_fail_open() -> None:
    global _fail_open, _since
    if _since is None:
        _since = datetime.now(UTC).isoformat()
    _fail_open += 1


def snapshot(limit: int = 50) -> dict:
    return {
        "since": _since,
        "total": sum(_by_reason.values()),
        "by_reason": dict(_by_reason),
        "top_countries": [{"country": c, "count": n} for c, n in _by_country.most_common(20)],
        "fail_open_allows": _fail_open,
        "recent": list(_recent)[:limit],
    }


def prometheus_series() -> tuple[dict[str, int], dict[str, int], int]:
    """(by_reason, by_country, fail_open) for the Prometheus export."""
    return dict(_by_reason), dict(_by_country), _fail_open
