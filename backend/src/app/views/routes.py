"""Cross-instance aggregate views: global VPN overview, firmware compliance."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import Instance, User
from app.opnsense.client import OPNsenseError
from app.opnsense.registry import registry
from app.opnsense.schemas import FirmwareStatus, IPsecTunnel

router = APIRouter(tags=["views"])


# --- Global VPN Overview ---------------------------------------------------

class GlobalTunnel(BaseModel):
    instance_id: int
    instance_name: str
    tunnel_id: str
    description: str
    remote: str
    local: str
    phase1_status: str
    bytes_in: int
    bytes_out: int


class GlobalVPNResponse(BaseModel):
    tunnels: list[GlobalTunnel]
    total: int
    up: int
    down: int


@router.get("/vpn/overview", response_model=GlobalVPNResponse)
async def global_vpn_overview(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> GlobalVPNResponse:
    """Fetch IPsec tunnels from ALL active instances in parallel."""
    instances = (
        await session.execute(
            select(Instance).where(Instance.deleted_at.is_(None))
        )
    ).scalars().all()

    async def fetch_tunnels(inst: Instance) -> list[GlobalTunnel]:
        try:
            client = await registry.get(inst)
            status = await client.ipsec_status()
            return [
                GlobalTunnel(
                    instance_id=inst.id,
                    instance_name=inst.name,
                    tunnel_id=t.id,
                    description=t.description,
                    remote=t.remote,
                    local=t.local,
                    phase1_status=t.phase1_status,
                    bytes_in=t.bytes_in,
                    bytes_out=t.bytes_out,
                )
                for t in status.tunnels
            ]
        except (OPNsenseError, Exception):
            return []

    results = await asyncio.gather(*(fetch_tunnels(i) for i in instances))
    all_tunnels = [t for group in results for t in group]
    up = sum(
        1 for t in all_tunnels
        if "established" in t.phase1_status.lower() or "connected" in t.phase1_status.lower()
    )
    return GlobalVPNResponse(
        tunnels=all_tunnels, total=len(all_tunnels), up=up, down=len(all_tunnels) - up
    )


# --- Firmware Compliance ---------------------------------------------------

class FirmwareEntry(BaseModel):
    instance_id: int
    instance_name: str
    location: str | None
    product_version: str
    product_latest: str
    upgrade_available: bool
    updates_available: int
    status_msg: str
    needs_reboot: bool
    last_check: str


class FirmwareComplianceResponse(BaseModel):
    instances: list[FirmwareEntry]
    total: int
    up_to_date: int
    outdated: int
    unknown: int


@router.get("/firmware/compliance", response_model=FirmwareComplianceResponse)
async def firmware_compliance(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> FirmwareComplianceResponse:
    """Fetch firmware status from ALL active instances in parallel."""
    instances = (
        await session.execute(
            select(Instance).where(Instance.deleted_at.is_(None))
        )
    ).scalars().all()

    async def fetch_fw(inst: Instance) -> FirmwareEntry | None:
        try:
            client = await registry.get(inst)
            fw = await client.firmware_status()
            return FirmwareEntry(
                instance_id=inst.id,
                instance_name=inst.name,
                location=inst.location,
                product_version=fw.product_version,
                product_latest=fw.product_latest,
                upgrade_available=fw.upgrade_available,
                updates_available=fw.updates_available,
                status_msg=fw.status_msg,
                needs_reboot=fw.needs_reboot,
                last_check=fw.last_check,
            )
        except (OPNsenseError, Exception):
            return FirmwareEntry(
                instance_id=inst.id,
                instance_name=inst.name,
                location=inst.location,
                product_version="?",
                product_latest="?",
                upgrade_available=False,
                updates_available=0,
                status_msg="unreachable",
                needs_reboot=False,
                last_check="",
            )

    results = await asyncio.gather(*(fetch_fw(i) for i in instances))
    entries = [r for r in results if r is not None]
    outdated = sum(1 for e in entries if e.upgrade_available)
    unknown = sum(1 for e in entries if e.product_version == "?")
    up_to_date = len(entries) - outdated - unknown

    return FirmwareComplianceResponse(
        instances=entries, total=len(entries),
        up_to_date=up_to_date, outdated=outdated, unknown=unknown,
    )
