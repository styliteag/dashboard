"""Gateway status, config backup, reboot, firewall log endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import User
from app.instances import service as inst_service
from app.opnsense.client import OPNsenseError
from app.opnsense.registry import registry
from app.opnsense.schemas import ActionResult, GatewayStatus

router = APIRouter(prefix="/instances/{instance_id}", tags=["system"])


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


@router.get("/gateways", response_model=list[GatewayStatus])
async def gateways(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[GatewayStatus]:
    inst = await inst_service.get_instance(session, instance_id)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        client = await registry.get(inst)
        return await client.gateway_status()
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@router.get("/config-backup")
async def config_backup(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> PlainTextResponse:
    """Download OPNsense config.xml."""
    inst = await inst_service.get_instance(session, instance_id)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        client = await registry.get(inst)
        xml = await client.download_config()
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    await write_audit(
        session,
        action="config.backup",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=_client_ip(request),
    )
    await session.commit()
    return PlainTextResponse(
        content=xml,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{inst.name}_config.xml"'},
    )


@router.post("/reboot", response_model=ActionResult)
async def reboot(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> ActionResult:
    inst = await inst_service.get_instance(session, instance_id)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        client = await registry.get(inst)
        result = await client.reboot()
    except OPNsenseError as exc:
        await write_audit(
            session, action="system.reboot", result="error", user_id=user.id,
            target_type="instance", target_id=str(instance_id),
            source_ip=_client_ip(request), detail={"error": str(exc)},
        )
        await session.commit()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    await write_audit(
        session, action="system.reboot", result="ok", user_id=user.id,
        target_type="instance", target_id=str(instance_id),
        source_ip=_client_ip(request),
    )
    await session.commit()
    return result


@router.get("/firewall-log")
async def firewall_log(
    instance_id: int,
    limit: int = Query(default=50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[dict]:
    """Fetch recent firewall log entries."""
    inst = await inst_service.get_instance(session, instance_id)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        client = await registry.get(inst)
        return await client.firewall_log(limit)
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
