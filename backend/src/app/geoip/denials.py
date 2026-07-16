"""Denial accounting for the GeoIP/CrowdSec gate — persistent, flood-proof.

Two tiers (DR-G9, migration 040):

- ``geoip_denial_stats`` — per (day, reason, country) aggregate, upserted by
  the flush job. Bounded by days × ~4 reasons × ~250 countries, it counts
  EVERY denial and is the source of truth for totals.
- ``geoip_denial_events`` — individual rows for the recent-denials table,
  hard-capped per flush interval (``_EVENTS_PER_FLUSH``): under a flood only
  a sample lands here while the aggregate still counts everything. Pruned by
  the flush job itself (batched, oldest-first, own ts index).

The request path only touches bounded in-memory buffers (a scanner cycling
random IPs can neither flood a table nor grow memory); a 15s scheduler job
flushes them with its own session. ``_totals``/``_total_countries`` mirror
the all-time sums (hydrated from the stats table at startup, incremented on
record) so the Prometheus counters stay monotonic ACROSS restarts without a
DB query per scrape.
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import GeoipDenialEvent, GeoipDenialStat
from app.geoip import lookup

log = structlog.get_logger("app.geoip")

_EVENTS_PER_FLUSH = 50  # row-sample cap per flush interval; aggregate counts all
_EVENT_RETENTION_DAYS = 30
_STATS_RETENTION_DAYS = 365
_PRUNE_BATCH = 10_000

_FAIL_OPEN_REASON = "fail_open"  # stats row for DR-G5 allows; not a denial

# --- request-path buffers (bounded) -------------------------------------------
_pending_events: deque[dict] = deque(maxlen=_EVENTS_PER_FLUSH)
_pending_agg: Counter[tuple[str, str]] = Counter()  # (reason, country) -> n

# All-time mirrors for Prometheus (hydrated + incremented; monotonic).
_totals: Counter[str] = Counter()
_total_countries: Counter[str] = Counter()
_total_fail_open = 0
_hydrated = False


def record(ip: str | None, country: str | None, path: str, reason: str) -> None:
    _pending_agg[(reason, country or "??")] += 1
    _totals[reason] += 1
    _total_countries[country or "??"] += 1
    _pending_events.append(
        {
            "ts": datetime.now(UTC),
            "ip": (ip or "?")[:45],
            "country": country,
            "path": path[:255],
            "reason": reason[:32],
        }
    )


def record_fail_open() -> None:
    global _total_fail_open
    _pending_agg[(_FAIL_OPEN_REASON, "??")] += 1
    _total_fail_open += 1


def prometheus_series() -> tuple[dict[str, int], dict[str, int], int]:
    """All-time (by_reason, by_country, fail_open) — monotonic across restarts."""
    return dict(_totals), dict(_total_countries), _total_fail_open


async def hydrate(session: AsyncSession) -> None:
    """Load all-time sums from the stats table into the Prometheus mirrors.

    Runs once at startup (before traffic); without it the counters would
    restart at 0 and long-term dashboards would see false resets."""
    global _hydrated, _total_fail_open
    rows = (
        await session.execute(
            select(
                GeoipDenialStat.reason,
                GeoipDenialStat.country,
                func.sum(GeoipDenialStat.count),
            ).group_by(GeoipDenialStat.reason, GeoipDenialStat.country)
        )
    ).all()
    for reason, country, total in rows:
        n = int(total or 0)
        if reason == _FAIL_OPEN_REASON:
            _total_fail_open += n
            continue
        _totals[reason] += n
        _total_countries[country] += n
    _hydrated = True
    log.info("geoip.denials_hydrated", reasons=dict(_totals), fail_open=_total_fail_open)


async def flush(session: AsyncSession) -> int:
    """Write pending buffers to the DB. Returns the number of aggregated denials.

    Caller (scheduler job) owns the commit. Buffers are swapped out first so a
    failed commit loses at most one interval — acceptable for statistics,
    and the Prometheus mirrors are incremented at record time regardless.
    """
    if not _pending_agg and not _pending_events:
        return 0
    agg = dict(_pending_agg)
    _pending_agg.clear()
    events = list(_pending_events)
    _pending_events.clear()

    bucket = datetime.now(UTC).date()
    for (reason, country), n in agg.items():
        # MariaDB-native upsert (repo rule: no ON CONFLICT idioms).
        await session.execute(
            text(
                "INSERT INTO geoip_denial_stats (bucket, reason, country, count) "
                "VALUES (:bucket, :reason, :country, :n) "
                "ON DUPLICATE KEY UPDATE count = count + :n"
            ),
            {"bucket": bucket, "reason": reason, "country": country, "n": n},
        )
    for e in events:
        session.add(GeoipDenialEvent(**e))
    await session.flush()
    return sum(agg.values())


async def prune(session: AsyncSession) -> None:
    """Retention: batched oldest-first deletes (unbounded DELETE gap-locks)."""
    event_cutoff = datetime.now(UTC) - timedelta(days=_EVENT_RETENTION_DAYS)
    while True:
        result = await session.execute(
            delete(GeoipDenialEvent).where(
                GeoipDenialEvent.id.in_(
                    select(GeoipDenialEvent.id)
                    .where(GeoipDenialEvent.ts < event_cutoff)
                    .order_by(GeoipDenialEvent.ts)
                    .limit(_PRUNE_BATCH)
                    .scalar_subquery()
                )
            )
        )
        await session.commit()
        if (result.rowcount or 0) < _PRUNE_BATCH:
            break
    stats_cutoff = (datetime.now(UTC) - timedelta(days=_STATS_RETENTION_DAYS)).date()
    await session.execute(delete(GeoipDenialStat).where(GeoipDenialStat.bucket < stats_cutoff))
    await session.commit()


async def snapshot(session: AsyncSession, limit: int = 50) -> dict:
    """Persistent view for the Access page (stats table + recent events).

    Pending not-yet-flushed denials are folded in so the UI never lags the
    15s flush interval on the counters."""
    rows = (
        await session.execute(
            select(
                GeoipDenialStat.reason,
                GeoipDenialStat.country,
                func.sum(GeoipDenialStat.count),
            ).group_by(GeoipDenialStat.reason, GeoipDenialStat.country)
        )
    ).all()
    by_reason: Counter[str] = Counter()
    by_country: Counter[str] = Counter()
    fail_open = 0
    for reason, country, total in rows:
        n = int(total or 0)
        if reason == _FAIL_OPEN_REASON:
            fail_open += n
            continue
        by_reason[reason] += n
        by_country[country] += n
    for (reason, country), n in _pending_agg.items():
        if reason == _FAIL_OPEN_REASON:
            fail_open += n
        else:
            by_reason[reason] += n
            by_country[country] += n

    since = await session.scalar(select(func.min(GeoipDenialStat.bucket)))
    recent_rows = (
        (
            await session.execute(
                select(GeoipDenialEvent).order_by(GeoipDenialEvent.ts.desc()).limit(limit)
            )
        )
        .scalars()
        .all()
    )

    def _hover_name(ip: str, code: str | None) -> str | None:
        # Display-only hover label; attached only while the live DB still
        # agrees with the code stored at denial time.
        live_code, name = lookup.country_display(ip)
        return name if live_code == code else None

    pending = [
        {
            "at": e["ts"].isoformat(),
            "ip": e["ip"],
            "country": e["country"],
            "country_name": _hover_name(e["ip"], e["country"]),
            "path": e["path"],
            "reason": e["reason"],
        }
        for e in reversed(_pending_events)
    ]
    persisted = [
        {
            "at": e.ts.isoformat(),
            "ip": e.ip,
            "country": e.country,
            "country_name": _hover_name(e.ip, e.country),
            "path": e.path,
            "reason": e.reason,
        }
        for e in recent_rows
    ]
    return {
        "since": since.isoformat() if since else None,
        "total": sum(by_reason.values()),
        "by_reason": dict(by_reason),
        "top_countries": [{"country": c, "count": n} for c, n in by_country.most_common(20)],
        "fail_open_allows": fail_open,
        "recent": (pending + persisted)[:limit],
    }


async def flush_job() -> None:
    """Scheduler entry point (15s): flush buffers with an own session."""
    from app.db.base import get_sessionmaker  # local import: avoid cycles

    if not _pending_agg and not _pending_events:
        return
    async with get_sessionmaker()() as session:
        n = await flush(session)
        await session.commit()
    if n:
        log.debug("geoip.denials_flushed", denials=n)


async def prune_job() -> None:
    """Scheduler entry point (daily): retention for events + stats."""
    from app.db.base import get_sessionmaker

    async with get_sessionmaker()() as session:
        await prune(session)
