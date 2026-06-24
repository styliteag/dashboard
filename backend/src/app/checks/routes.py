"""REST: evaluated service checks for an instance (drives green/red + Checkmk)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.auth.deps import current_user
from app.checks import ServiceCheck, evaluate_checks
from app.db.base import get_session
from app.db.models import Instance, User
from app.opnsense.registry import registry
from app.opnsense.schemas import (
    FirmwareStatus,
    GatewayStatus,
    IPsecServiceStatus,
    SystemStatus,
)

router = APIRouter(tags=["checks"])


async def _safe(coro_fn, default):
    try:
        return await coro_fn()
    except Exception:  # noqa: BLE001 — one failing aspect must not sink the rest
        return default


async def _gather(
    inst: Instance, instance_id: int
) -> tuple[
    SystemStatus, list[GatewayStatus] | None, IPsecServiceStatus | None, FirmwareStatus | None
]:
    """Collect the four aspects: from the agent-hub cache (push) or live (direct)."""
    if inst.agent_mode:
        return (
            hub.get_last_status(instance_id) or SystemStatus(),
            hub.get_last_gateways(instance_id),
            hub.get_last_ipsec(instance_id),
            hub.get_last_firmware(instance_id),
        )
    client = await registry.get(inst)
    return (
        await _safe(client.poll_status, SystemStatus()),
        await _safe(client.gateway_status, None),
        await _safe(client.ipsec_status, None),
        await _safe(client.firmware_status, None),
    )


@router.get("/instances/{instance_id}/checks", response_model=list[ServiceCheck])
async def instance_checks(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[ServiceCheck]:
    """Evaluated OK/WARN/CRIT checks for one instance (memory, disks, gateways, IPsec, firmware)."""
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    sys_status, gateways, ipsec, firmware = await _gather(inst, instance_id)
    return evaluate_checks(sys_status, gateways, ipsec, firmware)
