"""Standalone connectivity ping-monitor endpoints.

CRUD for tunnel-independent (source, destination) ping probes. All state-changing
actions are audited and push the refreshed monitor set to the connected agent.
Agent-mode only — the probe runs on the firewall.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.connectivity import service as conn_service
from app.connectivity.schemas import (
    ConnMonitorCreate,
    ConnMonitorRead,
    ConnMonitorState,
    ConnMonitorUpdate,
    ConnPingTestRequest,
    ConnPingTestResult,
)
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances import service as inst_service
from app.net import client_ip

router = APIRouter(prefix="/instances/{instance_id}/connectivity", tags=["connectivity"])


async def _get_instance(instance_id: int, session: AsyncSession, user: User) -> Instance:
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="instance not found")
    return inst


@router.get("/monitors", response_model=list[ConnMonitorRead])
async def list_monitors(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[ConnMonitorRead]:
    """List the configured connectivity ping monitors for an instance."""
    await _get_instance(instance_id, session, user)
    monitors = await conn_service.list_monitors(session, instance_id)
    return [ConnMonitorRead.model_validate(m) for m in monitors]


@router.get("/status", response_model=list[ConnMonitorState])
async def connectivity_status(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[ConnMonitorState]:
    """Each configured monitor joined with its latest pushed ping result.

    The live result comes from the agent-hub cache, keyed by monitor id; a monitor
    with no result yet (just added, or agent hasn't pushed) reports ``none``.
    """
    await _get_instance(instance_id, session, user)
    monitors = await conn_service.list_monitors(session, instance_id)
    results = {r.id: r for r in (hub.get_last_connectivity(instance_id) or [])}
    out: list[ConnMonitorState] = []
    for m in monitors:
        state = ConnMonitorState.model_validate(m)
        r = results.get(m.id)
        if r is not None:
            state = state.model_copy(
                update={
                    "ping_state": r.ping_state,
                    "ping_rtt_ms": r.ping_rtt_ms,
                    "ping_loss_pct": r.ping_loss_pct,
                    "ping_ts": r.ping_ts,
                }
            )
        out.append(state)
    return out


@router.post("/monitors/test", response_model=ConnPingTestResult)
async def test_monitor(
    instance_id: int,
    body: ConnPingTestRequest,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> ConnPingTestResult:
    """Run a one-off ping via the agent so the user can validate source/dest before saving.

    Agent-mode only — the probe runs on the firewall (a direct-mode instance has
    no agent to ping from).
    """
    inst = await _get_instance(instance_id, session, user)
    if not inst.agent_mode:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ping test requires agent mode",
        )
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )
    result = await agent.send_command(
        "connectivity.ping_test",
        {"source": body.source, "destination": body.destination, "ping_count": body.ping_count},
        timeout=20,
    )
    return ConnPingTestResult(
        ok=bool(result.get("success")),
        ping_state=result.get("ping_state", "error"),
        ping_rtt_ms=result.get("ping_rtt_ms"),
        ping_loss_pct=result.get("ping_loss_pct"),
        message=result.get("output", ""),
    )


@router.post("/monitors", response_model=ConnMonitorRead, status_code=status.HTTP_201_CREATED)
async def create_monitor(
    instance_id: int,
    body: ConnMonitorCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> ConnMonitorRead:
    """Create a connectivity monitor and push the updated set to the agent."""
    await _get_instance(instance_id, session, user)
    try:
        monitor = await conn_service.create_monitor(session, instance_id, body)
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a connectivity monitor with this name already exists",
        ) from exc
    await write_audit(
        session,
        action="connectivity.monitor.create",
        result="ok",
        user_id=user.id,
        target_type="connectivity_monitor",
        target_id=str(monitor.id),
        source_ip=client_ip(request),
        detail={"instance_id": instance_id, "name": monitor.name},
    )
    await session.commit()
    await session.refresh(monitor)
    await conn_service.push_to_agent(session, instance_id)
    return ConnMonitorRead.model_validate(monitor)


@router.patch("/monitors/{monitor_id}", response_model=ConnMonitorRead)
async def update_monitor(
    instance_id: int,
    monitor_id: int,
    body: ConnMonitorUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> ConnMonitorRead:
    """Update a connectivity monitor and push the updated set to the agent."""
    await _get_instance(instance_id, session, user)
    monitor = await conn_service.get_monitor(session, instance_id, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="monitor not found")
    try:
        monitor = await conn_service.update_monitor(session, monitor, body)
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a connectivity monitor with this name already exists",
        ) from exc
    await write_audit(
        session,
        action="connectivity.monitor.update",
        result="ok",
        user_id=user.id,
        target_type="connectivity_monitor",
        target_id=str(monitor_id),
        source_ip=client_ip(request),
        detail={"instance_id": instance_id, "monitor_id": monitor_id},
    )
    await session.commit()
    await session.refresh(monitor)
    await conn_service.push_to_agent(session, instance_id)
    return ConnMonitorRead.model_validate(monitor)


@router.delete("/monitors/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_monitor(
    instance_id: int,
    monitor_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> None:
    """Delete a connectivity monitor and push the updated set to the agent."""
    await _get_instance(instance_id, session, user)
    monitor = await conn_service.get_monitor(session, instance_id, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="monitor not found")
    await conn_service.delete_monitor(session, monitor)
    await write_audit(
        session,
        action="connectivity.monitor.delete",
        result="ok",
        user_id=user.id,
        target_type="connectivity_monitor",
        target_id=str(monitor_id),
        source_ip=client_ip(request),
        detail={"instance_id": instance_id, "monitor_id": monitor_id},
    )
    await session.commit()
    await conn_service.push_to_agent(session, instance_id)
