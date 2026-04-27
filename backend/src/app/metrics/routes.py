"""Status + metrics endpoints (US-3.1 .. US-3.4).

GET /api/instances/{id}/status    — current status snapshot from last poll
GET /api/instances/{id}/metrics   — historical time-series for a metric
GET /api/overview                 — global KPI tiles
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import Instance, User
from app.metrics.store import read_metrics
from app.opnsense.registry import registry
from app.opnsense.schemas import SystemStatus

router = APIRouter(tags=["status"])


# ----- Schemas ---------------------------------------------------------------

class OverviewResponse(BaseModel):
    total: int
    online: int
    offline: int
    degraded: int  # had a recent error but also a recent success


class MetricPoint(BaseModel):
    ts: str
    value: float


class MetricResponse(BaseModel):
    metric: str
    instance_id: int
    points: list[MetricPoint]


# ----- Time-range helpers ---------------------------------------------------

RANGE_BUCKETS: dict[str, tuple[timedelta, int]] = {
    "1h": (timedelta(hours=1), 0),       # raw
    "6h": (timedelta(hours=6), 60),       # 1min buckets
    "24h": (timedelta(hours=24), 300),    # 5min buckets
    "7d": (timedelta(days=7), 900),       # 15min buckets
    "30d": (timedelta(days=30), 3600),    # 1h buckets
}


# ----- Endpoints ------------------------------------------------------------

@router.get("/instances/{instance_id}/status", response_model=SystemStatus)
async def instance_status(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> SystemStatus:
    """Live status from the last poll snapshot. Calls poll_status() on demand if
    the cached client exists, to give a near-real-time view."""
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        client = await registry.get(inst)
        return await client.poll_status()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"poll failed: {exc}",
        ) from exc


@router.get("/instances/{instance_id}/metrics", response_model=MetricResponse)
async def instance_metrics(
    instance_id: int,
    metric: str = Query(default="cpu.total", description="Metric name"),
    range: str = Query(default="24h", description="Time range: 1h, 6h, 24h, 7d, 30d"),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> MetricResponse:
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    td, bucket = RANGE_BUCKETS.get(range, RANGE_BUCKETS["24h"])
    end = datetime.now(timezone.utc)
    start = end - td

    points_raw = await read_metrics(session, instance_id, metric, start, end, bucket)
    points = [MetricPoint(ts=p["ts"], value=p["value"]) for p in points_raw]
    return MetricResponse(metric=metric, instance_id=instance_id, points=points)


@router.get("/overview", response_model=OverviewResponse)
async def overview(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> OverviewResponse:
    """Global KPI tiles (US-3.4)."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)

    # Subqueries for each bucket
    base = select(Instance).where(Instance.deleted_at.is_(None))
    total = (await session.execute(select(func.count()).select_from(base.subquery()))).scalar() or 0

    online_q = base.where(Instance.last_success_at >= cutoff).where(
        (Instance.last_error_at.is_(None)) | (Instance.last_success_at > Instance.last_error_at)
    )
    online = (await session.execute(select(func.count()).select_from(online_q.subquery()))).scalar() or 0

    degraded_q = base.where(Instance.last_success_at >= cutoff).where(
        Instance.last_error_at >= cutoff
    ).where(Instance.last_error_at >= Instance.last_success_at)
    degraded = (await session.execute(select(func.count()).select_from(degraded_q.subquery()))).scalar() or 0

    offline = total - online - degraded
    return OverviewResponse(total=total, online=online, offline=offline, degraded=degraded)
