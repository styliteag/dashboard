"""Repository + agent-push for standalone connectivity ping monitors.

CRUD lives here so the routes stay thin; ``monitors_payload`` and
``push_to_agent`` build and deliver the agent's ``config_update`` frame. The wire
payload carries the row ``id`` so the agent can echo it back on each result,
keeping the check key ``connectivity:<id>`` stable.
"""

from __future__ import annotations

import contextlib

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectivity.schemas import ConnMonitorCreate, ConnMonitorUpdate
from app.db.models import ConnectivityMonitor

log = structlog.get_logger("app.connectivity")


async def list_monitors(session: AsyncSession, instance_id: int) -> list[ConnectivityMonitor]:
    rows = (
        await session.execute(
            select(ConnectivityMonitor)
            .where(ConnectivityMonitor.instance_id == instance_id)
            .order_by(ConnectivityMonitor.id)
        )
    ).scalars()
    return list(rows.all())


async def get_monitor(
    session: AsyncSession, instance_id: int, monitor_id: int
) -> ConnectivityMonitor | None:
    monitor = await session.get(ConnectivityMonitor, monitor_id)
    if monitor is None or monitor.instance_id != instance_id:
        return None
    return monitor


async def create_monitor(
    session: AsyncSession, instance_id: int, data: ConnMonitorCreate
) -> ConnectivityMonitor:
    monitor = ConnectivityMonitor(instance_id=instance_id, **data.model_dump())
    session.add(monitor)
    await session.flush()
    return monitor


async def update_monitor(
    session: AsyncSession, monitor: ConnectivityMonitor, data: ConnMonitorUpdate
) -> ConnectivityMonitor:
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(monitor, field, value)
    await session.flush()
    return monitor


async def delete_monitor(session: AsyncSession, monitor: ConnectivityMonitor) -> None:
    await session.delete(monitor)


def monitors_payload(monitors: list[ConnectivityMonitor]) -> list[dict]:
    """Serialize monitors into the agent's ``config_update`` shape.

    Includes ``id`` (unlike the IPsec push) so the agent echoes it back per
    result and the check key stays stable across renames / same-dest monitors.
    """
    return [
        {
            "id": int(m.id),
            "name": m.name,
            "source": m.source,
            "destination": m.destination,
            "enabled": bool(m.enabled),
            "ping_count": int(m.ping_count),
        }
        for m in monitors
    ]


async def push_to_agent(session: AsyncSession, instance_id: int) -> None:
    """Push the instance's current monitor set to its connected agent (best-effort).

    No-op when the agent is offline — it pulls the fresh set on its next hello.
    """
    from app.agent_hub.hub import hub  # local import: avoid hub ↔ connectivity cycle

    agent = hub.get(instance_id)
    if agent is None:
        return
    monitors = await list_monitors(session, instance_id)
    payload = {"connectivity_monitors": monitors_payload(monitors)}
    with contextlib.suppress(Exception):
        await agent.ws.send_json({"type": "config_update", "data": payload})
        log.debug("connectivity.config_pushed", instance_id=instance_id, count=len(monitors))
