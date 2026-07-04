"""Global read API for aggregated critical log events across all instances.

Events are extracted at ingest (see app.logs.events) and stored per
``(instance, log_name)``; this endpoint filters by syslog severity and the
caller's group scope. Default ceiling is 3 (errors) — prod data shows sev<=2
is typically empty, so a stricter default would render a blank page.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import require_admin
from app.auth.scope import Principal, scope_clause
from app.db.base import get_session
from app.db.models import Instance, LogEvent, User

router = APIRouter(prefix="/logs", tags=["logs"])


class LogEventItem(BaseModel):
    instance_id: int
    instance_name: str
    log_name: str
    severity: int
    program: str
    pattern: str
    sample: str
    count: int
    last_ts: str
    updated_at: datetime


async def list_log_events(
    session: AsyncSession, principal: Principal, max_severity: int
) -> list[tuple[LogEvent, str]]:
    """(event, instance_name) pairs within the principal's group scope."""
    q = (
        select(LogEvent, Instance.name)
        .join(Instance, Instance.id == LogEvent.instance_id)
        .where(LogEvent.severity <= max_severity, Instance.deleted_at.is_(None))
        .order_by(LogEvent.severity.asc(), LogEvent.count.desc())
    )
    clause = scope_clause(principal)
    if clause is not None:
        q = q.where(clause)
    rows = await session.execute(q)
    return [(event, name) for event, name in rows.all()]


@router.get("/events", response_model=list[LogEventItem])
async def global_log_events(
    max_severity: int = Query(3, ge=0, le=7),
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> list[LogEventItem]:
    rows = await list_log_events(session, admin, max_severity)
    return [
        LogEventItem(
            instance_id=event.instance_id,
            instance_name=name,
            log_name=event.log_name,
            severity=event.severity,
            program=event.program,
            pattern=event.pattern,
            sample=event.sample,
            count=event.count,
            last_ts=event.last_ts,
            updated_at=event.updated_at,
        )
        for event, name in rows
    ]
