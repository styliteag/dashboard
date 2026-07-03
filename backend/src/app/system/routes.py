"""Gateway status, config backup, reboot, firewall log endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.db.base import get_session
from app.db.models import AuditLog, User
from app.instances import service as inst_service
from app.net import client_ip
from app.securepoint.client import SecurepointError
from app.xsense.client import OPNsenseError
from app.xsense.registry import registry
from app.xsense.schemas import ActionResult, CertInfo, ConfigInfo, GatewayStatus, ServiceInfo

router = APIRouter(prefix="/instances/{instance_id}", tags=["system"])


@router.get("/certificates", response_model=list[CertInfo])
async def certificates(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[CertInfo]:
    """Certificates and their expiry (agent push only). Direct/Securepoint = empty."""
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if inst.agent_mode:
        return hub.get_last_certs(instance_id) or []
    return []


class ConfigInfoResponse(BaseModel):
    """Last config change (from the agent's config.xml <revision>) plus the last
    time a config backup was downloaded through the dashboard (from the audit log)."""

    revision_time: str = ""
    revision_description: str = ""
    revision_user: str = ""
    last_backup_at: str | None = None


@router.get("/config-info", response_model=ConfigInfoResponse)
async def config_info(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> ConfigInfoResponse:
    """Config-change metadata + last backup time. Revision is agent-push only."""
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    rev = ConfigInfo()
    if inst.agent_mode:
        cached = hub.get_last_status(instance_id)
        if cached is not None:
            rev = cached.config

    last_backup = (
        await session.execute(
            select(AuditLog.ts)
            .where(
                AuditLog.action == "config.backup",
                AuditLog.target_id == str(instance_id),
                AuditLog.result == "ok",
            )
            .order_by(AuditLog.ts.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    return ConfigInfoResponse(
        revision_time=rev.revision_time,
        revision_description=rev.revision_description,
        revision_user=rev.revision_user,
        last_backup_at=last_backup.isoformat() if last_backup else None,
    )


@router.get("/services", response_model=list[ServiceInfo])
async def services(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[ServiceInfo]:
    """Per-service running state. Agent mode: last push from the hub cache.
    Direct/Securepoint poll does not carry services → empty list."""
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if inst.agent_mode:
        return hub.get_last_services(instance_id) or []
    return []


@router.get("/gateways", response_model=list[GatewayStatus])
async def gateways(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[GatewayStatus]:
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if inst.agent_mode:
        return hub.get_last_gateways(instance_id) or []

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
    """Download OPNsense config.xml. Agent mode: request via agent command."""
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if inst.agent_mode:
        agent = hub.get(instance_id)
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
            )
        result = await agent.send_command("config.backup")
        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=result.get("output", "backup failed"),
            )
        xml = result.get("config_xml", "")
        await write_audit(
            session,
            action="config.backup",
            result="ok",
            user_id=user.id,
            target_type="instance",
            target_id=str(instance_id),
            source_ip=client_ip(request),
        )
        await session.commit()
        return PlainTextResponse(
            content=xml,
            media_type="application/xml",
            headers={"Content-Disposition": f'attachment; filename="{inst.name}_config.xml"'},
        )

    try:
        client = await registry.get(inst)
        xml = await client.download_config()
    except (OPNsenseError, SecurepointError) as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    await write_audit(
        session,
        action="config.backup",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
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
    user: User = Depends(require_write),
) -> ActionResult:
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if inst.agent_mode:
        agent = hub.get(instance_id)
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
            )
        result = await agent.send_command("reboot")
        await write_audit(
            session,
            action="system.reboot",
            result="ok",
            user_id=user.id,
            target_type="instance",
            target_id=str(instance_id),
            source_ip=client_ip(request),
        )
        await session.commit()
        return ActionResult(success=result.get("success", False), message=result.get("output", ""))

    try:
        client = await registry.get(inst)
        result = await client.reboot()
    except OPNsenseError as exc:
        await write_audit(
            session,
            action="system.reboot",
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
        action="system.reboot",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return result


@router.get("/firewall-log")
async def firewall_log(
    instance_id: int,
    limit: int = Query(default=50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[dict]:
    """Fetch recent firewall log entries. Agent mode: return cached push data."""
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if inst.agent_mode:
        cached = hub.get_last_firewall_log(instance_id) or []
        return cached[-limit:]

    try:
        client = await registry.get(inst)
        return await client.firewall_log(limit)
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
