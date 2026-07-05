"""Read API for stored config.xml versions: list, diff, download.

Gating matches the existing live ``GET /instances/{id}/config-backup`` route:
any scoped user (``current_user`` + ``get_instance``) — the live download
already hands out the full config.xml, so the stored versions follow the same
policy. Decryption happens server-side only; downloads are audit-logged with
the same ``config.backup`` action as the live download.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import current_user
from app.configbackup.store import (
    config_text,
    get_config_backup,
    list_config_backups,
    unified_config_diff,
)
from app.db.base import get_session
from app.db.models import User
from app.instances.service import get_instance
from app.net import client_ip

router = APIRouter(prefix="/instances", tags=["config-backups"])


def _safe_filename(name: str) -> str:
    """Instance names are free-form; headers are not — keep a conservative set
    so a crafted name can't break the quoted-string or inject header bytes."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")


class ConfigBackupItem(BaseModel):
    id: int
    collected_at: datetime
    sha256: str
    bytes: int
    source: str


class ConfigBackupDiff(BaseModel):
    from_id: int
    to_id: int
    from_collected_at: datetime
    to_collected_at: datetime
    diff: str
    truncated: bool


@router.get("/{instance_id}/config-backups", response_model=list[ConfigBackupItem])
async def list_instance_config_backups(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[ConfigBackupItem]:
    if await get_instance(session, instance_id, user) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    rows = await list_config_backups(session, instance_id)
    return [
        ConfigBackupItem(
            id=r.id, collected_at=r.collected_at, sha256=r.sha256, bytes=r.bytes, source=r.source
        )
        for r in rows
    ]


# Declared before the /{backup_id}/... route so "diff" never parses as an id.
@router.get("/{instance_id}/config-backups/diff", response_model=ConfigBackupDiff)
async def diff_config_backups(
    instance_id: int,
    request: Request,
    from_id: int = Query(...),
    to_id: int = Query(...),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> ConfigBackupDiff:
    """Unified diff between two stored versions ("what changed on this box?")."""
    if await get_instance(session, instance_id, user) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    old = await get_config_backup(session, instance_id, from_id)
    new = await get_config_backup(session, instance_id, to_id)
    if old is None or new is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    # The diff shows config content (changed lines are where new secrets land),
    # so it is audit-logged like a download.
    await write_audit(
        session,
        action="config.diff",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
    )
    await session.commit()

    def _decrypt_and_diff() -> tuple[str, bool]:
        # Fernet decrypt + SequenceMatcher are CPU-bound on multi-MB configs —
        # run off the event loop so one diff can't stall API + agent ingest.
        return unified_config_diff(
            config_text(old),
            config_text(new),
            f"config.xml @ {old.collected_at:%Y-%m-%d %H:%M:%S}",
            f"config.xml @ {new.collected_at:%Y-%m-%d %H:%M:%S}",
        )

    diff, truncated = await asyncio.to_thread(_decrypt_and_diff)
    return ConfigBackupDiff(
        from_id=old.id,
        to_id=new.id,
        from_collected_at=old.collected_at,
        to_collected_at=new.collected_at,
        diff=diff,
        truncated=truncated,
    )


@router.get("/{instance_id}/config-backups/{backup_id}/download")
async def download_config_backup(
    instance_id: int,
    backup_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> PlainTextResponse:
    """Download one stored version as XML (disaster recovery)."""
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    row = await get_config_backup(session, instance_id, backup_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    await write_audit(
        session,
        action="config.backup",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    stamp = f"{row.collected_at:%Y%m%d-%H%M%S}"
    fname = _safe_filename(inst.name) or f"instance-{instance_id}"
    return PlainTextResponse(
        content=await asyncio.to_thread(config_text, row),
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{fname}_config_{stamp}.xml"'},
    )
