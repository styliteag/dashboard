"""Read API for stored logfile snapshots (metadata + anonymized preview).

Raw log content never leaves the backend: the anonymized endpoint applies
``app.llm.anonymize`` server-side so the browser only ever sees scrubbed text,
which it then hands to ``POST /api/llm/analyze``.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import require_admin
from app.db.base import get_session
from app.db.models import User
from app.instances.service import get_instance
from app.llm.anonymize import anonymize
from app.logs.context import build_analysis_text, build_context_text
from app.logs.store import latest_per_name, list_logfiles

router = APIRouter(prefix="/instances", tags=["logs"])


class LogfileItem(BaseModel):
    name: str
    collected_at: datetime
    bytes: int


class AnonymizedLogs(BaseModel):
    text: str
    names: list[str]


@router.get("/{instance_id}/logs", response_model=list[LogfileItem])
async def list_instance_logs(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> list[LogfileItem]:
    if await get_instance(session, instance_id, admin) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    rows = await list_logfiles(session, instance_id)
    return [LogfileItem(name=r.name, collected_at=r.collected_at, bytes=r.bytes) for r in rows]


@router.get("/{instance_id}/logs/anonymized", response_model=AnonymizedLogs)
async def anonymized_instance_logs(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> AnonymizedLogs:
    inst = await get_instance(session, instance_id, admin)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    snapshot = inst.status_snapshot
    rows = await latest_per_name(session, instance_id)
    text = build_analysis_text(snapshot, rows)
    names = (["telemetry"] if build_context_text(snapshot) else []) + [r.name for r in rows]
    return AnonymizedLogs(text=anonymize(text), names=names)
