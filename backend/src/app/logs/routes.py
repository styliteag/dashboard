"""Read API for stored logfile snapshots (metadata, raw content, anonymized preview).

Admins can view the raw snapshots via the content endpoint. The LLM path stays
scrubbed: the anonymized endpoint applies ``app.llm.anonymize`` server-side so
only anonymized text is ever handed to ``POST /api/llm/analyze``.
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
from app.logs.store import get_logfile, latest_per_name, list_logfiles

router = APIRouter(prefix="/instances", tags=["logs"])


class LogfileItem(BaseModel):
    id: int
    name: str
    collected_at: datetime
    bytes: int


class LogfileContent(BaseModel):
    id: int
    name: str
    collected_at: datetime
    bytes: int
    content: str


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
    return [
        LogfileItem(id=r.id, name=r.name, collected_at=r.collected_at, bytes=r.bytes) for r in rows
    ]


@router.get("/{instance_id}/logs/{logfile_id}/content", response_model=LogfileContent)
async def instance_log_content(
    instance_id: int,
    logfile_id: int,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> LogfileContent:
    if await get_instance(session, instance_id, admin) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    row = await get_logfile(session, instance_id, logfile_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return LogfileContent(
        id=row.id,
        name=row.name,
        collected_at=row.collected_at,
        bytes=row.bytes,
        content=row.content,
    )


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
