"""Read API for stored logfile snapshots (metadata + anonymized preview).

Raw log content never leaves the backend: the anonymized endpoint applies
``app.llm.anonymize`` server-side so the browser only ever sees scrubbed text,
which it then hands to ``POST /api/llm/analyze``.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.deps import require_admin
from app.db.base import get_session
from app.db.models import User
from app.llm.anonymize import anonymize
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
    _admin: User = Depends(require_admin),
) -> list[LogfileItem]:
    rows = await list_logfiles(session, instance_id)
    return [LogfileItem(name=r.name, collected_at=r.collected_at, bytes=r.bytes) for r in rows]


@router.get("/{instance_id}/logs/anonymized", response_model=AnonymizedLogs)
async def anonymized_instance_logs(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> AnonymizedLogs:
    rows = await latest_per_name(session, instance_id)
    combined = "\n\n".join(f"===== {r.name} =====\n{r.content}" for r in rows)
    return AnonymizedLogs(text=anonymize(combined), names=[r.name for r in rows])
