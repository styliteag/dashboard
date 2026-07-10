"""Entity-comment endpoints — operator notes on tunnels, monitors, firmware, certs.

Read is any-session; writes ride the ``require_write`` rung and are audited with
the comment text verbatim (same policy as Instance.notes, which is allowlisted in
the instance audit). Out-of-scope instances 404 (no existence oracle); the
overview read drops out-of-scope rows via the caller's visible-instance set (the
same pattern as the connectivity overview).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.comments import store
from app.comments.schemas import CommentKind, CommentRead, CommentSet
from app.db.base import get_session
from app.db.models import EntityComment, User
from app.instances import service as inst_service
from app.net import client_ip

router = APIRouter(tags=["comments"])


def _iso_utc(dt: datetime | None) -> str | None:
    """MariaDB DATETIME reads back naive-but-UTC — tag it so browsers don't parse
    the bare string as local time (same rationale as agent_hub.routes.management)."""
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).isoformat()


def _read(row: EntityComment) -> CommentRead:
    return CommentRead(
        instance_id=row.instance_id,
        kind=row.kind,
        entity_key=row.entity_key,
        comment=row.comment,
        updated_by=row.updated_by,
        updated_at=_iso_utc(row.updated_at),
    )


@router.get("/comments", response_model=list[CommentRead])
async def comments_overview(
    kind: CommentKind | None = Query(default=None),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[CommentRead]:
    """All comments across the caller's visible instances (optionally one kind).

    Overview pages (VPN, connectivity, firmware, certs) merge these client-side by
    (instance_id, entity_key). Out-of-scope rows drop out via the visible-id set —
    a zero-group user therefore sees none.
    """
    instances = await inst_service.list_instances(session, user)
    visible = {i.id for i in instances}
    rows = await store.list_all(session, kind)
    return [_read(r) for r in rows if r.instance_id in visible]


@router.get("/instances/{instance_id}/comments", response_model=list[CommentRead])
async def instance_comments(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[CommentRead]:
    """All comments of one instance (every kind — per-instance tabs filter)."""
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return [_read(r) for r in await store.list_for_instance(session, instance_id)]


@router.put("/instances/{instance_id}/comments")
async def set_comment(
    instance_id: int,
    body: CommentSet,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Upsert one comment; an empty/whitespace comment deletes the entry."""
    inst = await inst_service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    text = body.comment.strip()
    try:
        if text:
            await store.upsert(
                session, instance_id, body.kind, body.entity_key, text, user.username
            )
            action = "comment.set"
        else:
            removed = await store.remove(session, instance_id, body.kind, body.entity_key)
            if not removed:
                return {"ok": True}  # deleting a comment that never existed is a no-op
            action = "comment.delete"
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="comment was changed concurrently, retry",
        ) from exc
    await write_audit(
        session,
        action=action,
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        # Comment text is operator-authored prose (like Instance.notes, which the
        # instance audit allowlists verbatim) — no secrets pass through here.
        detail={"kind": body.kind, "entity_key": body.entity_key, "comment": text},
    )
    await session.commit()
    return {"ok": True}
