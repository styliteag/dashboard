"""Repository + agent-push for IPsec Phase-2 ping monitors.

CRUD lives here so the routes stay thin; ``monitors_payload`` and
``push_to_agent`` build and deliver the agent's ``config_update`` frame.
"""

from __future__ import annotations

import contextlib

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IPsecPingMonitor
from app.ipsec.ping_schemas import PingMonitorCreate, PingMonitorUpdate

log = structlog.get_logger("app.ipsec.ping")


async def list_monitors(session: AsyncSession, instance_id: int) -> list[IPsecPingMonitor]:
    rows = (
        await session.execute(
            select(IPsecPingMonitor)
            .where(IPsecPingMonitor.instance_id == instance_id)
            .order_by(IPsecPingMonitor.id)
        )
    ).scalars()
    return list(rows.all())


async def get_monitor(
    session: AsyncSession, instance_id: int, monitor_id: int
) -> IPsecPingMonitor | None:
    monitor = await session.get(IPsecPingMonitor, monitor_id)
    if monitor is None or monitor.instance_id != instance_id:
        return None
    return monitor


async def create_monitor(
    session: AsyncSession, instance_id: int, data: PingMonitorCreate
) -> IPsecPingMonitor:
    monitor = IPsecPingMonitor(instance_id=instance_id, **data.model_dump())
    session.add(monitor)
    await session.flush()
    return monitor


async def update_monitor(
    session: AsyncSession, monitor: IPsecPingMonitor, data: PingMonitorUpdate
) -> IPsecPingMonitor:
    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(monitor, field, value)
    await session.flush()
    return monitor


async def delete_monitor(session: AsyncSession, monitor: IPsecPingMonitor) -> None:
    await session.delete(monitor)


def monitors_payload(monitors: list[IPsecPingMonitor]) -> list[dict]:
    """Serialize monitors into the agent's ``config_update`` shape."""
    return [
        {
            "tunnel_id": m.tunnel_id,
            "child_name": m.child_name,
            "local_ts": m.local_ts,
            "remote_ts": m.remote_ts,
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
    from app.agent_hub.hub import hub  # local import: avoid hub ↔ ipsec import cycle

    agent = hub.get(instance_id)
    if agent is None:
        return
    monitors = await list_monitors(session, instance_id)
    payload = {"ipsec_ping_monitors": monitors_payload(monitors)}
    with contextlib.suppress(Exception):
        await agent.ws.send_json({"type": "config_update", "data": payload})
        log.debug("ipsec.ping_config_pushed", instance_id=instance_id, count=len(monitors))
