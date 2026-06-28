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
from app.db.models import CheckEvent


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
) -> list[CheckEvent]:
    """Most-recent-first check history for one instance (capped)."""
    result = await session.execute(
        select(CheckEvent)
        .where(CheckEvent.instance_id == instance_id)
        .order_by(CheckEvent.ts.desc(), CheckEvent.id.desc())
        .limit(limit)
    )
    return list(result.scalars().all())
