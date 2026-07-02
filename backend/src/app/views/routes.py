"""Cross-instance aggregate views: global VPN overview, firmware compliance."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.auth.deps import current_user
from app.checks.staleness import staleness_for
from app.db.base import get_session
from app.db.models import ConnectivityMonitor, Instance, User
from app.settings.store import effective_settings
from app.xsense.client import OPNsenseError
from app.xsense.registry import registry
from app.xsense.schemas import IPsecChild

router = APIRouter(tags=["views"])

# Hard per-instance ceiling for the cross-instance fan-outs below: one slow or
# half-reachable direct-mode box must not stall the whole aggregate. Agent-mode
# instances read from the in-memory hub and never hit this.
_FETCH_TIMEOUT = 8.0


# --- Global VPN Overview ---------------------------------------------------


class GlobalTunnel(BaseModel):
    instance_id: int
    instance_name: str
    tunnel_id: str
    unique_id: str  # active IKE_SA id — needed to disconnect (terminate) from the overview
    description: str
    remote: str
    local: str
    phase1_status: str
    phase2_up: int
    phase2_total: int
    seconds_established: int
    bytes_in: int
    bytes_out: int
    tags: list[str] = []  # the owning instance's tags — for filtering the overview
    agent_mode: bool = False  # ping monitors are agent-only; UI hides the affordance otherwise
    # Deep-link support: the UI builds a "open IPsec status on the firewall" link
    # from these — /status_ipsec.php (pfSense) vs /ui/ipsec/sessions (OPNsense).
    device_type: str = ""
    base_url: str = ""
    # Agent-staleness overlay: when True the owning instance's agent has gone
    # silent, so phase1_status/children here are last-known, not live — the UI
    # mutes the row and flags it rather than trusting a stale "established".
    stale: bool = False
    stale_seconds: int | None = None
    children: list[IPsecChild] = []
    ike_init_spi: str = ""
    ike_resp_spi: str = ""
    # The matched other end of this tunnel (another managed instance), if found.
    peer_instance_id: int | None = None
    peer_instance_name: str | None = None
    peer_tunnel_id: str | None = None


def _attach_peers(tunnels: list[GlobalTunnel]) -> None:
    """Link the two ends of the same tunnel across instances (mutates in place).

    Primary key: the IKE cookie pair (initiator+responder SPI) — both peers report
    the IDENTICAL pair, and it survives NAT. Fallback: the reversed transport-IP
    pair (A.local==B.remote && A.remote==B.local), which also covers down /
    pre-establish tunnels that have no live SPI yet. SPIs rotate on rekey but both
    ends rotate together, so a 30s poll keeps them in sync.
    """
    by_ike: dict[tuple[str, str], list[GlobalTunnel]] = {}
    by_ep: dict[tuple[str, str], list[GlobalTunnel]] = {}
    for t in tunnels:
        if t.ike_init_spi and t.ike_resp_spi:
            by_ike.setdefault((t.ike_init_spi, t.ike_resp_spi), []).append(t)
        if t.local and t.remote:
            by_ep.setdefault((t.local, t.remote), []).append(t)
    for t in tunnels:
        peer: GlobalTunnel | None = None
        if t.ike_init_spi and t.ike_resp_spi:
            peer = next(
                (
                    p
                    for p in by_ike.get((t.ike_init_spi, t.ike_resp_spi), [])
                    if p.instance_id != t.instance_id
                ),
                None,
            )
        if peer is None and t.local and t.remote:
            peer = next(
                (p for p in by_ep.get((t.remote, t.local), []) if p.instance_id != t.instance_id),
                None,
            )
        if peer is not None:
            t.peer_instance_id = peer.instance_id
            t.peer_instance_name = peer.instance_name
            t.peer_tunnel_id = peer.tunnel_id


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
        (await session.execute(select(Instance).where(Instance.deleted_at.is_(None))))
        .scalars()
        .all()
    )
    settings = effective_settings()
    now = datetime.now(UTC)

    async def fetch_tunnels(inst: Instance) -> list[GlobalTunnel]:
        try:
            # Agent-mode instances have no direct OPNsense client; their IPsec
            # status lives in the agent hub cache (last push). Same branch as
            # the firmware compliance / per-instance endpoints.
            if inst.agent_mode:
                status = hub.get_last_ipsec(inst.id)
            else:
                client = await registry.get(inst)
                status = await asyncio.wait_for(client.ipsec_status(), _FETCH_TIMEOUT)
            if status is None:
                return []
            s = staleness_for(inst, settings, now)
            return [
                GlobalTunnel(
                    instance_id=inst.id,
                    instance_name=inst.name,
                    tunnel_id=t.id,
                    unique_id=t.unique_id,
                    description=t.description,
                    remote=t.remote,
                    local=t.local,
                    phase1_status=t.phase1_status,
                    phase2_up=t.phase2_up,
                    phase2_total=t.phase2_total,
                    seconds_established=t.seconds_established,
                    bytes_in=t.bytes_in,
                    bytes_out=t.bytes_out,
                    tags=inst.tags or [],
                    agent_mode=inst.agent_mode,
                    device_type=inst.device_type or "",
                    base_url=inst.base_url or "",
                    stale=bool(s and s.stale),
                    stale_seconds=s.age_seconds if s else None,
                    children=t.children,
                    ike_init_spi=t.ike_init_spi,
                    ike_resp_spi=t.ike_resp_spi,
                )
                for t in status.tunnels
            ]
        except (OPNsenseError, Exception):
            return []

    results = await asyncio.gather(*(fetch_tunnels(i) for i in instances))
    all_tunnels = [t for group in results for t in group]
    _attach_peers(all_tunnels)
    up = sum(
        1
        for t in all_tunnels
        if "established" in t.phase1_status.lower() or "connected" in t.phase1_status.lower()
    )
    return GlobalVPNResponse(
        tunnels=all_tunnels, total=len(all_tunnels), up=up, down=len(all_tunnels) - up
    )


# --- Global Connectivity Overview ------------------------------------------


class GlobalConnMonitor(BaseModel):
    instance_id: int
    instance_name: str
    id: int
    name: str
    source: str
    destination: str
    enabled: bool
    tags: list[str] = []
    # Agent-staleness overlay: when True the owning instance's agent has gone
    # silent, so ping_state here is last-known, not live — the UI mutes the row.
    stale: bool = False
    stale_seconds: int | None = None
    ping_state: str = "none"  # none | ok | fail | error
    ping_rtt_ms: float | None = None
    ping_loss_pct: float | None = None
    ping_ts: str | None = None


class GlobalConnectivityResponse(BaseModel):
    monitors: list[GlobalConnMonitor]
    total: int
    ok: int
    down: int  # ping_state == "fail"
    error: int


@router.get("/connectivity/overview", response_model=GlobalConnectivityResponse)
async def global_connectivity_overview(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> GlobalConnectivityResponse:
    """Every standalone connectivity monitor across all instances, joined with its
    latest pushed ping state from the agent-hub cache. Pure DB + in-memory — no
    appliance round-trips (the firewalls do the pinging, the agent pushes results).
    """
    instances = (
        (await session.execute(select(Instance).where(Instance.deleted_at.is_(None))))
        .scalars()
        .all()
    )
    by_id = {i.id: i for i in instances}
    conn_cache = {iid: {r.id: r for r in (hub.get_last_connectivity(iid) or [])} for iid in by_id}
    settings = effective_settings()
    now = datetime.now(UTC)

    monitors = (
        (
            await session.execute(
                select(ConnectivityMonitor).order_by(
                    ConnectivityMonitor.instance_id, ConnectivityMonitor.id
                )
            )
        )
        .scalars()
        .all()
    )

    out: list[GlobalConnMonitor] = []
    for m in monitors:
        inst = by_id.get(m.instance_id)
        if inst is None:
            continue
        r = conn_cache.get(inst.id, {}).get(m.id)
        s = staleness_for(inst, settings, now)
        out.append(
            GlobalConnMonitor(
                instance_id=inst.id,
                instance_name=inst.name,
                id=m.id,
                name=m.name,
                source=m.source,
                destination=m.destination,
                enabled=m.enabled,
                tags=inst.tags or [],
                stale=bool(s and s.stale),
                stale_seconds=s.age_seconds if s else None,
                ping_state=(r.ping_state if r else "none"),
                ping_rtt_ms=(r.ping_rtt_ms if r else None),
                ping_loss_pct=(r.ping_loss_pct if r else None),
                ping_ts=(r.ping_ts if r else None),
            )
        )

    ok = sum(1 for x in out if x.ping_state == "ok")
    down = sum(1 for x in out if x.ping_state == "fail")
    error = sum(1 for x in out if x.ping_state == "error")
    return GlobalConnectivityResponse(monitors=out, total=len(out), ok=ok, down=down, error=error)


# --- Firmware Compliance ---------------------------------------------------


class FirmwareEntry(BaseModel):
    instance_id: int
    instance_name: str
    location: str | None
    product_version: str
    branch: str = ""  # pfSense update branch / software train
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
        (await session.execute(select(Instance).where(Instance.deleted_at.is_(None))))
        .scalars()
        .all()
    )

    async def fetch_fw(inst: Instance) -> FirmwareEntry | None:
        try:
            # Agent-mode instances have no direct OPNsense client; their firmware
            # status lives in the agent hub cache (last push). Mirror the
            # per-instance endpoint (firmware/routes.py) which branches the same way.
            if inst.agent_mode:
                fw = hub.get_last_firmware(inst.id)
            else:
                client = await registry.get(inst)
                fw = await asyncio.wait_for(client.firmware_status(), _FETCH_TIMEOUT)
            if fw is None or not fw.product_version:
                raise ValueError("no firmware data")
            return FirmwareEntry(
                instance_id=inst.id,
                instance_name=inst.name,
                location=inst.location,
                product_version=fw.product_version,
                branch=getattr(fw, "branch", "") or "",
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
                branch="",
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
        instances=entries,
        total=len(entries),
        up_to_date=up_to_date,
        outdated=outdated,
        unknown=unknown,
    )
