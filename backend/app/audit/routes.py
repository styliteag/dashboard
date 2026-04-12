"""Audit log read endpoint (US-6.1). Read-only, no delete via API."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import AuditLog, User

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEntry(BaseModel):
    id: int
    ts: str
    user_id: int | None
    username: str | None = None
    action: str
    target_type: str | None
    target_id: str | None
    request_id: str | None
    result: str
    detail: dict | None
    source_ip: str | None


class AuditPage(BaseModel):
    items: list[AuditEntry]
    total: int
    page: int
    page_size: int


@router.get("", response_model=AuditPage)
async def list_audit(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    action: str | None = Query(default=None, description="Filter by action prefix, e.g. 'auth' or 'ipsec.connect'"),
    instance_id: int | None = Query(default=None),
    hours: int | None = Query(default=None, description="Only show entries from the last N hours"),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> AuditPage:
    base = select(AuditLog)

    if action:
        base = base.where(AuditLog.action.startswith(action))
    if instance_id is not None:
        base = base.where(AuditLog.detail["instance_id"].as_integer() == instance_id)
    if hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        base = base.where(AuditLog.ts >= cutoff)

    # Count
    count_q = select(func.count()).select_from(base.subquery())
    total = (await session.execute(count_q)).scalar() or 0

    # Fetch page with optional user join
    rows_q = (
        base.order_by(AuditLog.ts.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await session.execute(rows_q)).scalars().all()

    # Resolve usernames in a single query
    user_ids = {r.user_id for r in rows if r.user_id is not None}
    usernames: dict[int, str] = {}
    if user_ids:
        users = (
            await session.execute(select(User.id, User.username).where(User.id.in_(user_ids)))
        ).all()
        usernames = {u.id: u.username for u in users}

    items = [
        AuditEntry(
            id=r.id,
            ts=r.ts.isoformat(),
            user_id=r.user_id,
            username=usernames.get(r.user_id) if r.user_id else None,
            action=r.action,
            target_type=r.target_type,
            target_id=r.target_id,
            request_id=r.request_id,
            result=r.result,
            detail=r.detail,
            source_ip=r.source_ip,
        )
        for r in rows
    ]
    return AuditPage(items=items, total=total, page=page, page_size=page_size)
