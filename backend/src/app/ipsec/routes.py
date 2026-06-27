"""IPsec tunnel management endpoints (US-4.1 .. US-4.5).

All state-changing actions (connect/disconnect/restart) are audited.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import Instance, User
from app.devices.protocol import SupportsDiagnose, SupportsIPsec
from app.instances import service as inst_service
from app.ipsec import ping_service
from app.ipsec.event_store import read_tunnel_events
from app.ipsec.ping_schemas import (
    PingMonitorCreate,
    PingMonitorRead,
    PingMonitorUpdate,
    PingTestRequest,
    PingTestResult,
)
from app.net import client_ip
from app.securepoint.client import SecurepointError
from app.xsense.client import OPNsenseError
from app.xsense.registry import registry
from app.xsense.schemas import (
    ActionResult,
    DiagnosisSection,
    IPsecDiagnosis,
    IPsecServiceStatus,
)

router = APIRouter(prefix="/instances/{instance_id}/ipsec", tags=["ipsec"])


def _ipsec_client(client: object) -> SupportsIPsec:
    """Narrow a device client to the IPsec capability or 501 if unsupported."""
    if not isinstance(client, SupportsIPsec):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="IPsec not supported for this device type",
        )
    return client


async def _get_instance(instance_id: int, session: AsyncSession) -> Instance:
    inst = await inst_service.get_instance(session, instance_id)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="instance not found")
    return inst


class TunnelActionResponse(BaseModel):
    success: bool
    message: str
    tunnel_id: str


@router.get("", response_model=IPsecServiceStatus)
async def ipsec_status(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> IPsecServiceStatus:
    """List all IPsec tunnels with status. Agent mode: return cached push data."""
    inst = await _get_instance(instance_id, session)

    if inst.agent_mode:
        cached = hub.get_last_ipsec(instance_id)
        return cached if cached is not None else IPsecServiceStatus()

    try:
        client = _ipsec_client(await registry.get(inst))
        return await client.ipsec_status()
    except (OPNsenseError, SecurepointError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@router.get("/{tunnel_id}/diagnose", response_model=IPsecDiagnosis)
async def ipsec_diagnose(
    instance_id: int,
    tunnel_id: str,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> IPsecDiagnosis:
    """Readable diagnostic bundle for one tunnel (config, SAs, IPsec log, peer ping).

    Agent mode: the agent gathers on-box (swanctl + strongSwan log + ping) and
    pushes the result over its WebSocket. Direct mode: Securepoint gathers via SSH.
    """
    inst = await _get_instance(instance_id, session)

    if inst.agent_mode:
        agent = hub.get(instance_id)
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
            )
        result = await agent.send_command("ipsec.diagnose", {"tunnel_id": tunnel_id})
        rows = result.get("sections") or []
        return IPsecDiagnosis(
            tunnel_id=tunnel_id,
            sections=[
                DiagnosisSection(title=str(r.get("title", "")), content=str(r.get("content", "")))
                for r in rows
                if isinstance(r, dict)
            ],
        )

    client = await registry.get(inst)
    if not isinstance(client, SupportsDiagnose):
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="diagnostics not available for this device type",
        )
    try:
        return await client.ipsec_diagnose(tunnel_id)
    except (OPNsenseError, SecurepointError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


class TunnelHistoryEvent(BaseModel):
    ts: str
    tunnel_id: str
    child_name: str
    event_type: str
    old_value: str
    new_value: str


@router.get("/{tunnel_id}/history", response_model=list[TunnelHistoryEvent])
async def ipsec_tunnel_history(
    instance_id: int,
    tunnel_id: str,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[TunnelHistoryEvent]:
    """Recorded state-change history for one tunnel, most recent first.

    Populated by the agent-push ingest (push mode); direct-API instances have no
    history yet and return an empty list.
    """
    await _get_instance(instance_id, session)
    limit = max(1, min(limit, 500))
    rows = await read_tunnel_events(session, instance_id, tunnel_id, limit)
    return [
        TunnelHistoryEvent(
            ts=row.ts.isoformat(),
            tunnel_id=row.tunnel_id,
            child_name=row.child_name,
            event_type=row.event_type,
            old_value=row.old_value,
            new_value=row.new_value,
        )
        for row in rows
    ]


@router.post("/connect/{tunnel_id}", response_model=TunnelActionResponse)
async def ipsec_connect(
    instance_id: int,
    tunnel_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> TunnelActionResponse:
    """Connect a single IPsec tunnel. Agent mode: send command to agent."""
    inst = await _get_instance(instance_id, session)

    if inst.agent_mode:
        agent = hub.get(instance_id)
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
            )
        result = await agent.send_command("ipsec.connect", {"tunnel_id": tunnel_id})
        ok = result.get("success", False)
        await write_audit(
            session,
            action="ipsec.connect",
            result="ok" if ok else "error",
            user_id=user.id,
            target_type="ipsec_tunnel",
            target_id=tunnel_id,
            source_ip=client_ip(request),
            detail={"instance_id": instance_id},
        )
        await session.commit()
        return TunnelActionResponse(
            success=ok, message=result.get("output", ""), tunnel_id=tunnel_id
        )

    try:
        client = _ipsec_client(await registry.get(inst))
        result = await client.ipsec_connect(tunnel_id)
    except OPNsenseError as exc:
        await write_audit(
            session,
            action="ipsec.connect",
            result="error",
            user_id=user.id,
            target_type="ipsec_tunnel",
            target_id=tunnel_id,
            source_ip=client_ip(request),
            detail={"instance_id": instance_id, "error": str(exc)},
        )
        await session.commit()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    await write_audit(
        session,
        action="ipsec.connect",
        result="ok" if result.success else "error",
        user_id=user.id,
        target_type="ipsec_tunnel",
        target_id=tunnel_id,
        source_ip=client_ip(request),
        detail={"instance_id": instance_id, "message": result.message},
    )
    await session.commit()
    return TunnelActionResponse(success=result.success, message=result.message, tunnel_id=tunnel_id)


@router.post("/disconnect/{tunnel_id}", response_model=TunnelActionResponse)
async def ipsec_disconnect(
    instance_id: int,
    tunnel_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> TunnelActionResponse:
    """Disconnect a single IPsec tunnel. Agent mode: send command to agent."""
    inst = await _get_instance(instance_id, session)

    if inst.agent_mode:
        agent = hub.get(instance_id)
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
            )
        result = await agent.send_command("ipsec.disconnect", {"tunnel_id": tunnel_id})
        ok = result.get("success", False)
        await write_audit(
            session,
            action="ipsec.disconnect",
            result="ok" if ok else "error",
            user_id=user.id,
            target_type="ipsec_tunnel",
            target_id=tunnel_id,
            source_ip=client_ip(request),
            detail={"instance_id": instance_id},
        )
        await session.commit()
        return TunnelActionResponse(
            success=ok, message=result.get("output", ""), tunnel_id=tunnel_id
        )

    try:
        client = _ipsec_client(await registry.get(inst))
        result = await client.ipsec_disconnect(tunnel_id)
    except OPNsenseError as exc:
        await write_audit(
            session,
            action="ipsec.disconnect",
            result="error",
            user_id=user.id,
            target_type="ipsec_tunnel",
            target_id=tunnel_id,
            source_ip=client_ip(request),
            detail={"instance_id": instance_id, "error": str(exc)},
        )
        await session.commit()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    await write_audit(
        session,
        action="ipsec.disconnect",
        result="ok" if result.success else "error",
        user_id=user.id,
        target_type="ipsec_tunnel",
        target_id=tunnel_id,
        source_ip=client_ip(request),
        detail={"instance_id": instance_id, "message": result.message},
    )
    await session.commit()
    return TunnelActionResponse(success=result.success, message=result.message, tunnel_id=tunnel_id)


@router.post("/restart", response_model=ActionResult)
async def ipsec_restart(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> ActionResult:
    """Restart the IPsec service. Agent mode: send command to agent."""
    inst = await _get_instance(instance_id, session)

    if inst.agent_mode:
        agent = hub.get(instance_id)
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
            )
        result = await agent.send_command("ipsec.restart")
        ok = result.get("success", False)
        await write_audit(
            session,
            action="ipsec.restart",
            result="ok" if ok else "error",
            user_id=user.id,
            target_type="instance",
            target_id=str(instance_id),
            source_ip=client_ip(request),
        )
        await session.commit()
        return ActionResult(success=ok, message=result.get("output", ""))

    try:
        client = _ipsec_client(await registry.get(inst))
        result = await client.ipsec_restart()
    except OPNsenseError as exc:
        await write_audit(
            session,
            action="ipsec.restart",
            result="error",
            user_id=user.id,
            target_type="instance",
            target_id=str(instance_id),
            source_ip=client_ip(request),
            detail={"error": str(exc)},
        )
        await session.commit()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    await write_audit(
        session,
        action="ipsec.restart",
        result="ok" if result.success else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"message": result.message},
    )
    await session.commit()
    return result


# --- Phase-2 ping monitors (US: optional per-Phase-2 connectivity check) ------


@router.get("/ping-monitors", response_model=list[PingMonitorRead])
async def list_ping_monitors(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[PingMonitorRead]:
    """List the configured Phase-2 ping monitors for an instance."""
    await _get_instance(instance_id, session)
    monitors = await ping_service.list_monitors(session, instance_id)
    return [PingMonitorRead.model_validate(m) for m in monitors]


@router.post("/ping-monitors/test", response_model=PingTestResult)
async def test_ping_monitor(
    instance_id: int,
    body: PingTestRequest,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> PingTestResult:
    """Run a one-off ping via the agent so the user can validate source/dest before saving.

    Agent-mode only — the probe runs on the firewall (a direct-mode instance has
    no agent to ping from).
    """
    inst = await _get_instance(instance_id, session)
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
        "ipsec.ping_test",
        {"source": body.source, "destination": body.destination, "ping_count": body.ping_count},
        timeout=20,
    )
    return PingTestResult(
        ok=bool(result.get("success")),
        ping_state=result.get("ping_state", "error"),
        ping_rtt_ms=result.get("ping_rtt_ms"),
        ping_loss_pct=result.get("ping_loss_pct"),
        message=result.get("output", ""),
    )


@router.post("/ping-monitors", response_model=PingMonitorRead, status_code=status.HTTP_201_CREATED)
async def create_ping_monitor(
    instance_id: int,
    body: PingMonitorCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> PingMonitorRead:
    """Create a Phase-2 ping monitor and push the updated set to the agent."""
    await _get_instance(instance_id, session)
    try:
        monitor = await ping_service.create_monitor(session, instance_id, body)
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="a ping monitor for this Phase 2 already exists",
        ) from exc
    await write_audit(
        session,
        action="ipsec.ping_monitor.create",
        result="ok",
        user_id=user.id,
        target_type="ipsec_tunnel",
        target_id=monitor.tunnel_id,
        source_ip=client_ip(request),
        detail={"instance_id": instance_id, "child_name": monitor.child_name},
    )
    await session.commit()
    await session.refresh(monitor)
    await ping_service.push_to_agent(session, instance_id)
    return PingMonitorRead.model_validate(monitor)


@router.patch("/ping-monitors/{monitor_id}", response_model=PingMonitorRead)
async def update_ping_monitor(
    instance_id: int,
    monitor_id: int,
    body: PingMonitorUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> PingMonitorRead:
    """Update a Phase-2 ping monitor and push the updated set to the agent."""
    await _get_instance(instance_id, session)
    monitor = await ping_service.get_monitor(session, instance_id, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="monitor not found")
    monitor = await ping_service.update_monitor(session, monitor, body)
    await write_audit(
        session,
        action="ipsec.ping_monitor.update",
        result="ok",
        user_id=user.id,
        target_type="ipsec_tunnel",
        target_id=monitor.tunnel_id,
        source_ip=client_ip(request),
        detail={"instance_id": instance_id, "monitor_id": monitor_id},
    )
    await session.commit()
    await session.refresh(monitor)
    await ping_service.push_to_agent(session, instance_id)
    return PingMonitorRead.model_validate(monitor)


@router.delete("/ping-monitors/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ping_monitor(
    instance_id: int,
    monitor_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> None:
    """Delete a Phase-2 ping monitor and push the updated set to the agent."""
    await _get_instance(instance_id, session)
    monitor = await ping_service.get_monitor(session, instance_id, monitor_id)
    if monitor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="monitor not found")
    tunnel_id = monitor.tunnel_id
    await ping_service.delete_monitor(session, monitor)
    await write_audit(
        session,
        action="ipsec.ping_monitor.delete",
        result="ok",
        user_id=user.id,
        target_type="ipsec_tunnel",
        target_id=tunnel_id,
        source_ip=client_ip(request),
        detail={"instance_id": instance_id, "monitor_id": monitor_id},
    )
    await session.commit()
    await ping_service.push_to_agent(session, instance_id)
