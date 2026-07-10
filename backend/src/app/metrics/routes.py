"""Status + metrics endpoints (US-3.1 .. US-3.4).

GET /api/instances/{id}/status    — current status snapshot from last poll
GET /api/instances/{id}/metrics   — historical time-series for a metric
GET /api/overview                 — global KPI tiles
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.auth.deps import current_user
from app.auth.scope import scope_clause
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances.service import get_instance
from app.metrics.store import read_metrics, to_rate
from app.xsense.registry import registry
from app.xsense.schemas import SystemStatus

router = APIRouter(tags=["status"])


# ----- Schemas ---------------------------------------------------------------


class OverviewResponse(BaseModel):
    total: int
    online: int
    offline: int
    degraded: int  # had a recent error but also a recent success


class ExternalIpInfo(BaseModel):
    """Public IP(s) + NAT signal for the network tab.

    ``ipv4``/``ipv6`` are the agent's ipify probe (last known, sticky). ``source_ip``
    is the peer IP the hub saw on the agent's WS connect (None when disconnected).
    ``behind_nat`` is True when the box's public IPv4 is not one of its own
    interface addresses — a NAT gateway owns the public address."""

    ipv4: str | None = None
    ipv6: str | None = None
    checked_at: str | None = None
    source_ip: str | None = None
    behind_nat: bool = False
    connected: bool = False


class MetricPoint(BaseModel):
    ts: str
    value: float


class MetricResponse(BaseModel):
    metric: str
    instance_id: int
    points: list[MetricPoint]


# ----- Time-range helpers ---------------------------------------------------

RANGE_BUCKETS: dict[str, tuple[timedelta, int]] = {
    "1h": (timedelta(hours=1), 0),  # raw
    "6h": (timedelta(hours=6), 60),  # 1min buckets
    "24h": (timedelta(hours=24), 300),  # 5min buckets
    "7d": (timedelta(days=7), 900),  # 15min buckets
    "30d": (timedelta(days=30), 3600),  # 1h buckets
}


# ----- Endpoints ------------------------------------------------------------


@router.get("/instances/{instance_id}/status", response_model=SystemStatus)
async def instance_status(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> SystemStatus:
    """Current status snapshot.

    - Agent mode: return the last push received from the agent (in-memory cache).
      Falls back to an empty SystemStatus if the agent hasn't connected yet.
    - Polling mode: call poll_status() on demand for a near-real-time view.
    """
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if inst.agent_mode:
        cached = hub.get_last_status(instance_id)
        # Return cached status; if agent hasn't connected yet, return empty status
        return cached if cached is not None else SystemStatus()

    try:
        client = await registry.get(inst)
        return await client.poll_status()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"poll failed: {exc}",
        ) from exc


def _is_ipv4(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


@router.get("/instances/{instance_id}/external-ip", response_model=ExternalIpInfo)
async def instance_external_ip(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> ExternalIpInfo:
    """The box's public IPv4/IPv6 + a NAT indicator (agent mode).

    Composes the agent's ipify probe (hub cache) with the source IP the hub saw on
    connect and derives ``behind_nat``. Out-of-scope/missing instances 404 (no
    existence oracle) — same scope gate as ``/status``."""
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    ext = hub.get_last_external_ip(instance_id)
    source_ip = hub.get_source_ip(instance_id)
    status_snap = hub.get_last_status(instance_id)
    iface_addrs = {i.address for i in status_snap.interfaces if i.address} if status_snap else set()
    ipv4 = ext.ipv4 if ext else None
    # NAT judgement is IPv4-only (interface stats carry no IPv6): behind NAT when the
    # public IPv4 isn't configured on any interface. Prefer the ipify IPv4; fall back
    # to the observed source IP only when that is itself IPv4.
    candidate = ipv4 or (source_ip if _is_ipv4(source_ip) else None)
    behind_nat = bool(candidate and candidate not in iface_addrs)
    return ExternalIpInfo(
        ipv4=ipv4,
        ipv6=ext.ipv6 if ext else None,
        checked_at=ext.checked_at if ext else None,
        source_ip=source_ip,
        behind_nat=behind_nat,
        connected=hub.is_connected(instance_id),
    )


@router.get("/instances/{instance_id}/metrics", response_model=MetricResponse)
async def instance_metrics(
    instance_id: int,
    metric: str = Query(default="cpu.total", description="Metric name"),
    range: str = Query(default="24h", description="Time range: 1h, 6h, 24h, 7d, 30d"),
    rate: bool = Query(default=False, description="Differentiate a counter into a per-second rate"),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> MetricResponse:
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    td, bucket = RANGE_BUCKETS.get(range, RANGE_BUCKETS["24h"])
    end = datetime.now(UTC)
    start = end - td

    points_raw = await read_metrics(session, instance_id, metric, start, end, bucket)
    if rate:
        points_raw = to_rate(points_raw)
    points = [MetricPoint(ts=p["ts"], value=p["value"]) for p in points_raw]
    return MetricResponse(metric=metric, instance_id=instance_id, points=points)


@router.get("/overview", response_model=OverviewResponse)
async def overview(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> OverviewResponse:
    """KPI tiles over the caller's visible instances (US-3.4)."""
    cutoff = datetime.now(UTC) - timedelta(minutes=5)

    # Subqueries for each bucket
    base = select(Instance).where(Instance.deleted_at.is_(None))
    clause = scope_clause(user)
    if clause is not None:
        base = base.where(clause)
    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0

    online_q = base.where(Instance.last_success_at >= cutoff).where(
        (Instance.last_error_at.is_(None)) | (Instance.last_success_at > Instance.last_error_at)
    )
    online = (
        await session.execute(select(func.count()).select_from(online_q.subquery()))
    ).scalar() or 0

    degraded_q = (
        base.where(Instance.last_success_at >= cutoff)
        .where(Instance.last_error_at >= cutoff)
        .where(Instance.last_error_at >= Instance.last_success_at)
    )
    degraded = (
        await session.execute(select(func.count()).select_from(degraded_q.subquery()))
    ).scalar() or 0

    offline = total - online - degraded
    return OverviewResponse(total=total, online=online, offline=offline, degraded=degraded)
