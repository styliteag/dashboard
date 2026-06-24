"""IPsec tunnel management endpoints (US-4.1 .. US-4.5).

All state-changing actions (connect/disconnect/restart) are audited.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances import service as inst_service
from app.xsense.client import OPNsenseError
from app.xsense.registry import registry
from app.xsense.schemas import ActionResult, IPsecServiceStatus

router = APIRouter(prefix="/instances/{instance_id}/ipsec", tags=["ipsec"])


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


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
        client = await registry.get(inst)
        return await client.ipsec_status()
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


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
            source_ip=_client_ip(request),
            detail={"instance_id": instance_id},
        )
        await session.commit()
        return TunnelActionResponse(
            success=ok, message=result.get("output", ""), tunnel_id=tunnel_id
        )

    try:
        client = await registry.get(inst)
        result = await client.ipsec_connect(tunnel_id)
    except OPNsenseError as exc:
        await write_audit(
            session,
            action="ipsec.connect",
            result="error",
            user_id=user.id,
            target_type="ipsec_tunnel",
            target_id=tunnel_id,
            source_ip=_client_ip(request),
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
        source_ip=_client_ip(request),
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
            source_ip=_client_ip(request),
            detail={"instance_id": instance_id},
        )
        await session.commit()
        return TunnelActionResponse(
            success=ok, message=result.get("output", ""), tunnel_id=tunnel_id
        )

    try:
        client = await registry.get(inst)
        result = await client.ipsec_disconnect(tunnel_id)
    except OPNsenseError as exc:
        await write_audit(
            session,
            action="ipsec.disconnect",
            result="error",
            user_id=user.id,
            target_type="ipsec_tunnel",
            target_id=tunnel_id,
            source_ip=_client_ip(request),
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
        source_ip=_client_ip(request),
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
            source_ip=_client_ip(request),
        )
        await session.commit()
        return ActionResult(success=ok, message=result.get("output", ""))

    try:
        client = await registry.get(inst)
        result = await client.ipsec_restart()
    except OPNsenseError as exc:
        await write_audit(
            session,
            action="ipsec.restart",
            result="error",
            user_id=user.id,
            target_type="instance",
            target_id=str(instance_id),
            source_ip=_client_ip(request),
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
        source_ip=_client_ip(request),
        detail={"message": result.message},
    )
    await session.commit()
    return result
