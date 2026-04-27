"""Firmware management endpoints (US-5.1 .. US-5.3).

All actions are audited. Update is intentionally behind a separate POST so it
can't be triggered accidentally.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances import service as inst_service
from app.opnsense.client import OPNsenseError
from app.opnsense.registry import registry
from app.opnsense.schemas import ActionResult, FirmwareStatus, FirmwareUpgradeStatus

router = APIRouter(prefix="/instances/{instance_id}/firmware", tags=["firmware"])


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


@router.get("", response_model=FirmwareStatus)
async def firmware_status(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> FirmwareStatus:
    """Get firmware status and available updates (US-5.1)."""
    inst = await _get_instance(instance_id, session)
    try:
        client = await registry.get(inst)
        return await client.firmware_status()
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@router.post("/check", response_model=ActionResult)
async def firmware_check(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> ActionResult:
    """Trigger a firmware update check (US-5.2)."""
    inst = await _get_instance(instance_id, session)
    try:
        client = await registry.get(inst)
        result = await client.firmware_check()
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    await write_audit(
        session,
        action="firmware.check",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=_client_ip(request),
    )
    await session.commit()
    return result


@router.post("/update", response_model=ActionResult)
async def firmware_update(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> ActionResult:
    """Trigger firmware update (US-5.3). This kicks off the OPNsense updater
    which typically reboots the firewall. Handle with care."""
    inst = await _get_instance(instance_id, session)
    try:
        client = await registry.get(inst)
        result = await client.firmware_update()
    except OPNsenseError as exc:
        await write_audit(
            session,
            action="firmware.update",
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
        action="firmware.update",
        result="ok" if result.success else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=_client_ip(request),
        detail={"message": result.message},
    )
    await session.commit()
    return result


@router.get("/upgradestatus", response_model=FirmwareUpgradeStatus)
async def firmware_upgrade_status(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> FirmwareUpgradeStatus:
    """Poll the running upgrade progress (US-5.4)."""
    inst = await _get_instance(instance_id, session)
    try:
        client = await registry.get(inst)
        return await client.firmware_upgrade_status()
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
