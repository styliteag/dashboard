"""Persist and read service-check state-change events (alert/check history).

The agent-push ingest diffs each re-evaluation (``app.checks.history.diff_checks``)
and appends the resulting transitions here; the GUI reads the most recent rows for
an instance to render its check history. Repository-style: the only place that
touches the ``check_events`` table.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.checks.history import CheckTransition
from app.checks.models import CheckState
from app.db.models import CheckEvent

# Synthetic check key for instance online/offline transitions. Availability is not
# part of evaluate_checks (a push can't observe the offline edge), so it is recorded
# directly at the scheduler/hub flip sites — but into the same check_events table, so
# it shares the history route, pruning, and frontend timeline.
AVAILABILITY_KEY = "availability"


async def record_availability_event(
    session: AsyncSession,
    instance_id: int,
    ts: datetime,
    *,
    online: bool,
    summary: str,
) -> int:
    """Record an instance online/offline transition (online → OK, offline → CRIT).

    ``online`` is the *new* state. Recorded at the four flip sites (push recover,
    push stale, direct recover, direct fail); each is already guarded to fire only
    on a real transition, so this inherits one-row-per-change.
    """
    transition = CheckTransition(
        check_key=AVAILABILITY_KEY,
        old_state=int(CheckState.CRIT if online else CheckState.OK),
        new_state=int(CheckState.OK if online else CheckState.CRIT),
        summary=summary,
    )
    return await record_check_events(session, instance_id, ts, [transition])


async def record_check_events(
    session: AsyncSession,
    instance_id: int,
    ts: datetime,
    events: Sequence[CheckTransition],
) -> int:
    """Append diffed transitions for one instance at a shared timestamp.

    Caller owns the transaction (the agent-push handler commits once). Returns the
    number of rows queued. No-op on an empty diff.
    """
    if not events:
        return 0
    rows = [
        {
            "instance_id": instance_id,
            "ts": ts,
            "check_key": e.check_key[:128],
            "old_state": e.old_state,
            "new_state": e.new_state,
            "summary": e.summary[:255],
        }
        for e in events
    ]
    await session.execute(insert(CheckEvent), rows)
    return len(rows)


async def read_check_events(
    session: AsyncSession,
    instance_id: int,
    limit: int = 100,
    key_prefix: str | None = None,
) -> list[CheckEvent]:
    """Most-recent-first check history for one instance (capped).

    ``key_prefix`` restricts to keys starting with it (e.g. ``connectivity:`` for one
    surface, ``availability`` for online/offline) so one generic timeline can render
    a single surface.
    """
    stmt = select(CheckEvent).where(CheckEvent.instance_id == instance_id)
    if key_prefix:
        stmt = stmt.where(CheckEvent.check_key.startswith(key_prefix))
    stmt = stmt.order_by(CheckEvent.ts.desc(), CheckEvent.id.desc()).limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())
