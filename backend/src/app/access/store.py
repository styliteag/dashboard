"""Access accounting — who uses the dashboard, persistent and flood-proof.

ADR docs/access-log.md. Same two-tier shape as ``geoip/denials.py`` (DR-G9):

- ``access_stats`` — per (hour, principal) counter, upserted by the flush job.
  Counts EVERY request; cardinality is hours × active principals, so neither
  a polling UI nor a scanner can flood it.
- ``access_events`` — sampled per-request rows for the timeline, hard-capped
  per flush interval (``_EVENTS_PER_FLUSH``). Only user sessions are sampled:
  anon requests aggregate without IP rows (DR-AL8), API-key scrapes are
  uniform noise.
- ``auth_sessions`` — login-session bookkeeping (DR-AL3, NOT enforcement):
  created on login, ``last_seen_at`` stamped throttled via the flush job,
  expiry job turns the silent 12h cookie death into a real audit event
  (``auth.session_expired``, DR-AL4).

The request path only touches bounded in-memory buffers; a 15s scheduler job
flushes them with its own session. Process-local by design (single worker).
"""

from __future__ import annotations

import time
import uuid
from collections import Counter, deque
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.db.models import AccessEvent, AccessStat, AuthSession

log = structlog.get_logger("app.access")

_EVENTS_PER_FLUSH = 50  # row-sample cap per flush interval; aggregate counts all
_LAST_SEEN_THROTTLE_S = 60.0  # max one last_seen write per session per window
_PRUNE_BATCH = 10_000

# Keep in sync with SessionMiddleware max_age in main.py (imported there).
SESSION_MAX_AGE_S = 12 * 60 * 60
# A session counts as online while last_seen is younger than this — 5× the
# stamp throttle, so an active session can never flicker offline.
ONLINE_WINDOW_S = 5 * 60

# --- request-path buffers (bounded) -------------------------------------------
_pending_agg: Counter[tuple[str, str]] = Counter()  # (ptype, pkey) -> n
_pending_last_ip: dict[tuple[str, str], str] = {}
_pending_events: deque[dict] = deque(maxlen=_EVENTS_PER_FLUSH)
_pending_seen: dict[str, datetime] = {}  # sid -> last_seen to persist
_seen_stamped: dict[str, float] = {}  # sid -> monotonic of last stamp (throttle)


def new_sid() -> str:
    return uuid.uuid4().hex


def record_request(
    ptype: str,
    pkey: str,
    ip: str | None,
    method: str,
    path: str,
    status: int,
    *,
    user_id: int | None = None,
    sid: str | None = None,
) -> None:
    """Count one request; sample a detail row only for user sessions (DR-AL8)."""
    _pending_agg[(ptype, pkey)] += 1
    if ip:
        _pending_last_ip[(ptype, pkey)] = ip[:45]
    if ptype == "user":
        _pending_events.append(
            {
                "ts": datetime.now(UTC),
                "user_id": user_id,
                "ip": (ip or "?")[:45],
                "method": method[:8],
                "path": path[:255],
                "status": status,
            }
        )
    if sid:
        now = time.monotonic()
        last = _seen_stamped.get(sid)
        if last is None or now - last >= _LAST_SEEN_THROTTLE_S:
            _seen_stamped[sid] = now
            _pending_seen[sid] = datetime.now(UTC)


def record_apikey(key_id: int, ip: str | None) -> None:
    """API-key hit — aggregate only (scrapes are uniform, no sample rows)."""
    _pending_agg[("apikey", str(key_id))] += 1
    if ip:
        _pending_last_ip[("apikey", str(key_id))] = ip[:45]


async def flush(session: AsyncSession) -> int:
    """Write pending buffers to the DB. Returns the number of aggregated requests.

    Caller (scheduler job) owns the commit. Buffers are swapped out first so a
    failed commit loses at most one interval — acceptable for statistics.
    """
    if not _pending_agg and not _pending_events and not _pending_seen:
        return 0
    agg = dict(_pending_agg)
    _pending_agg.clear()
    last_ips = dict(_pending_last_ip)
    _pending_last_ip.clear()
    events = list(_pending_events)
    _pending_events.clear()
    seen = dict(_pending_seen)
    _pending_seen.clear()

    bucket = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    for (ptype, pkey), n in agg.items():
        # MariaDB-native upsert (repo rule: no ON CONFLICT idioms).
        await session.execute(
            text(
                "INSERT INTO access_stats (bucket, principal_type, principal_key, count, last_ip)"
                " VALUES (:bucket, :ptype, :pkey, :n, :ip)"
                " ON DUPLICATE KEY UPDATE count = count + :n,"
                " last_ip = COALESCE(:ip, last_ip)"
            ),
            {
                "bucket": bucket,
                "ptype": ptype,
                "pkey": pkey,
                "n": n,
                "ip": last_ips.get((ptype, pkey)),
            },
        )
    for e in events:
        session.add(AccessEvent(**e))
    for sid, ts in seen.items():
        await session.execute(
            update(AuthSession)
            .where(AuthSession.sid == sid, AuthSession.ended_at.is_(None))
            .values(last_seen_at=ts)
        )
    await session.flush()
    return sum(agg.values())


async def open_session(session: AsyncSession, *, sid: str, user_id: int, ip: str | None) -> None:
    """Registry row for a freshly minted login session (caller commits)."""
    now = datetime.now(UTC)
    session.add(AuthSession(sid=sid, user_id=user_id, ip=ip, created_at=now, last_seen_at=now))
    _seen_stamped[sid] = time.monotonic()
    await session.flush()


async def close_session(session: AsyncSession, sid: str | None, reason: str) -> None:
    """Mark a registry row ended (logout). Missing/unknown sid is a no-op —
    sessions minted before migration 041 have no row."""
    if not sid:
        return
    await session.execute(
        update(AuthSession)
        .where(AuthSession.sid == sid, AuthSession.ended_at.is_(None))
        .values(ended_at=datetime.now(UTC), end_reason=reason)
    )
    _seen_stamped.pop(sid, None)
    _pending_seen.pop(sid, None)


async def expire_sessions(session: AsyncSession) -> int:
    """Mark sessions older than the cookie max_age as expired + audit each.

    This is bookkeeping, not enforcement (DR-AL3/AL4): the cookie died on its
    own at max_age — here the previously silent auto-logout becomes a visible
    ``auth.session_expired`` event. Caller commits.
    """
    cutoff = datetime.now(UTC) - timedelta(seconds=SESSION_MAX_AGE_S)
    rows = (
        (
            await session.execute(
                select(AuthSession).where(
                    AuthSession.ended_at.is_(None), AuthSession.created_at < cutoff
                )
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    for s in rows:
        s.ended_at = now
        s.end_reason = "expired"
        _seen_stamped.pop(s.sid, None)
        await write_audit(
            session,
            action="auth.session_expired",
            result="ok",
            user_id=s.user_id,
            source_ip=s.ip,
        )
    if rows:
        await session.flush()
    return len(rows)


async def prune(
    session: AsyncSession, *, events_days: int, stats_days: int, sessions_days: int
) -> None:
    """Retention: batched oldest-first deletes (unbounded DELETE gap-locks)."""
    event_cutoff = datetime.now(UTC) - timedelta(days=events_days)
    while True:
        result = await session.execute(
            delete(AccessEvent).where(
                AccessEvent.id.in_(
                    select(AccessEvent.id)
                    .where(AccessEvent.ts < event_cutoff)
                    .order_by(AccessEvent.ts)
                    .limit(_PRUNE_BATCH)
                    .scalar_subquery()
                )
            )
        )
        await session.commit()
        if (result.rowcount or 0) < _PRUNE_BATCH:
            break
    stats_cutoff = datetime.now(UTC) - timedelta(days=stats_days)
    await session.execute(delete(AccessStat).where(AccessStat.bucket < stats_cutoff))
    await session.commit()
    sessions_cutoff = datetime.now(UTC) - timedelta(days=sessions_days)
    await session.execute(
        delete(AuthSession).where(
            AuthSession.ended_at.is_not(None), AuthSession.ended_at < sessions_cutoff
        )
    )
    await session.commit()


# --- scheduler entry points ----------------------------------------------------


async def flush_job() -> None:
    """15s: flush counters, samples and last_seen stamps with an own session."""
    from app.db.base import get_sessionmaker  # local import: avoid cycles

    if not _pending_agg and not _pending_events and not _pending_seen:
        return
    async with get_sessionmaker()() as session:
        n = await flush(session)
        await session.commit()
    if n:
        log.debug("access.flushed", requests=n)


async def expire_job() -> None:
    """5 min: turn max_age session deaths into audit events."""
    from app.db.base import get_sessionmaker

    async with get_sessionmaker()() as session:
        n = await expire_sessions(session)
        await session.commit()
    if n:
        log.info("access.sessions_expired", sessions=n)


async def prune_job() -> None:
    """Daily: retention for samples, aggregates and ended sessions."""
    from app.db.base import get_sessionmaker
    from app.settings.store import effective_settings

    settings = effective_settings()
    async with get_sessionmaker()() as session:
        await prune(
            session,
            events_days=int(settings.access_events_retention_days),
            stats_days=int(settings.access_stats_retention_days),
            sessions_days=int(settings.access_sessions_retention_days),
        )
