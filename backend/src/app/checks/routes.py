"""REST: evaluated service checks for an instance (drives green/red + Checkmk)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.auth.deps import read_principal
from app.checkmk.exclusions import is_excluded
from app.checks import ServiceCheck, evaluate_checks
from app.db.base import get_session
from app.db.models import CheckmkExportExclusion, Instance
from app.xsense.registry import registry
from app.xsense.schemas import (
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
    _principal=Depends(read_principal),
) -> list[ServiceCheck]:
    """Evaluated OK/WARN/CRIT checks for one instance (memory, disks, gateways, IPsec, firmware)."""
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    sys_status, gateways, ipsec, firmware = await _gather(inst, instance_id)
    return evaluate_checks(sys_status, gateways, ipsec, firmware)


@router.get("/export/checkmk")
async def export_checkmk(
    session: AsyncSession = Depends(get_session),
    _principal=Depends(read_principal),
) -> dict:
    """All instances' checks in one call — consumed by the Checkmk special agent.

    Push instances use the hub cache (cheap); direct instances are polled live,
    which can be slow with many of them (caching direct status is a follow-up).
    """
    rows = (
        (
            await session.execute(
                select(Instance).where(Instance.deleted_at.is_(None)).order_by(Instance.name)
            )
        )
        .scalars()
        .all()
    )

    rule_rows = (await session.execute(select(CheckmkExportExclusion))).scalars().all()
    rules = [(r.instance_id, r.target) for r in rule_rows]

    instances = []
    for inst in rows:
        sys_status, gateways, ipsec, firmware = await _gather(inst, inst.id)
        checks = [
            c
            for c in evaluate_checks(sys_status, gateways, ipsec, firmware)
            if not is_excluded(c.key, inst.id, rules)
        ]
        instances.append(
            {
                "instance_id": inst.id,
                "name": inst.name,
                "host": inst.name,  # piggyback host name
                "device_type": inst.device_type,
                "checks": [c.model_dump() for c in checks],
            }
        )
    return {"version": 1, "instances": instances}
