"""Firmware management endpoints (US-5.1 .. US-5.3).

All actions are audited. Update is intentionally behind a separate POST so it
can't be triggered accidentally.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances import service as inst_service
from app.net import client_ip
from app.xsense.client import OPNsenseError
from app.xsense.registry import registry
from app.xsense.schemas import ActionResult, FirmwareStatus, FirmwareUpgradeStatus

router = APIRouter(prefix="/instances/{instance_id}/firmware", tags=["firmware"])


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
    """Get firmware status. Agent mode: return last push from the agent."""
    inst = await _get_instance(instance_id, session)

    if inst.agent_mode:
        cached = hub.get_last_firmware(instance_id)
        return cached if cached is not None else FirmwareStatus()

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
    user: User = Depends(require_write),
) -> ActionResult:
    """Trigger a firmware update check. Agent mode: send command to agent."""
    inst = await _get_instance(instance_id, session)

    if inst.agent_mode:
        agent = hub.get(instance_id)
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
            )
        result_raw = await agent.send_command("firmware.check", timeout=90)
        output = result_raw.get("output", "")
        # Newer agents report the verdict explicitly; older ones only the output text.
        upgrade_available = result_raw.get("upgrade_available")
        if upgrade_available is None:
            upgrade_available = (
                "can be updated" in output.lower() or "updates available" in output.lower()
            )
        # firmware.check now returns the version too; fall back to what we already cached
        product_version = result_raw.get("product_version") or (
            hub.get_last_firmware(instance_id).product_version
            if hub.get_last_firmware(instance_id)
            else ""
        )
        branch = result_raw.get("branch") or (
            hub.get_last_firmware(instance_id).branch if hub.get_last_firmware(instance_id) else ""
        )
        known = result_raw.get("known_branches") or (
            hub.get_last_firmware(instance_id).known_branches
            if hub.get_last_firmware(instance_id)
            else []
        )
        import datetime as _dt

        hub.set_firmware(
            instance_id,
            FirmwareStatus(
                product_version=product_version,
                branch=branch,
                known_branches=known,
                product_latest=result_raw.get("product_latest") or product_version,
                upgrade_available=upgrade_available,
                updates_available=1 if upgrade_available else 0,
                status_msg=output[:500],
                last_check=_dt.datetime.now(_dt.UTC).isoformat(),
            ),
        )
        await write_audit(
            session,
            action="firmware.check",
            result="ok",
            user_id=user.id,
            target_type="instance",
            target_id=str(instance_id),
            source_ip=client_ip(request),
        )
        await session.commit()
        return ActionResult(success=True, message=output[:200] or "check complete")

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
        source_ip=client_ip(request),
    )
    await session.commit()
    return result


@router.post("/update", response_model=ActionResult)
async def firmware_update(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> ActionResult:
    """Trigger firmware update. Agent mode: send command to agent."""
    inst = await _get_instance(instance_id, session)

    if inst.firmware_locked:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="firmware updates are locked for this instance",
        )

    if inst.agent_mode:
        agent = hub.get(instance_id)
        if agent is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
            )
        result_raw = await agent.send_command("firmware.update")
        await write_audit(
            session,
            action="firmware.update",
            result="ok" if result_raw.get("success") else "error",
            user_id=user.id,
            target_type="instance",
            target_id=str(instance_id),
            source_ip=client_ip(request),
        )
        await session.commit()
        return ActionResult(
            success=result_raw.get("success", False), message=result_raw.get("output", "")[:200]
        )

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
            source_ip=client_ip(request),
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
        source_ip=client_ip(request),
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
    """Poll upgrade progress. Agent mode: not supported (returns empty)."""
    inst = await _get_instance(instance_id, session)

    if inst.agent_mode:
        return FirmwareUpgradeStatus(status="unknown", log=[])

    try:
        client = await registry.get(inst)
        return await client.firmware_upgrade_status()
    except OPNsenseError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
