"""Persist and read IPsec tunnel state-change events (history popup backing store).

The agent-push ingest diffs each snapshot (``app.ipsec.history.diff_ipsec``) and
appends the resulting transitions here; the GUI reads the most recent rows for a
single tunnel to render its history. Repository-style: the only place that
touches the ``ipsec_tunnel_events`` table.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IPsecTunnelEvent
from app.ipsec.history import TunnelEvent


async def record_tunnel_events(
    session: AsyncSession,
    instance_id: int,
    ts: datetime,
    events: Sequence[TunnelEvent],
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
            "tunnel_id": e.tunnel_id,
            "child_name": e.child_name,
            "ts": ts,
            "event_type": e.event_type,
            "old_value": e.old_value[:255],
            "new_value": e.new_value[:255],
        }
        for e in events
    ]
    await session.execute(insert(IPsecTunnelEvent), rows)
    return len(rows)


async def read_tunnel_events(
    session: AsyncSession,
    instance_id: int,
    tunnel_id: str,
    limit: int = 100,
) -> list[IPsecTunnelEvent]:
    """Most-recent-first history for one tunnel (capped). Uses ix_ipsec_event_lookup."""
    result = await session.execute(
        select(IPsecTunnelEvent)
        .where(
            IPsecTunnelEvent.instance_id == instance_id,
            IPsecTunnelEvent.tunnel_id == tunnel_id,
        )
        .order_by(IPsecTunnelEvent.ts.desc(), IPsecTunnelEvent.id.desc())
        .limit(limit)
    )
    return list(result.scalars().all())
