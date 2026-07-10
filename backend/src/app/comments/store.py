"""DB access for entity comments. Services flush(); the route owns commit()."""

from __future__ import annotations

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import EntityComment


async def list_for_instance(session: AsyncSession, instance_id: int) -> list[EntityComment]:
    """All comments of one instance (every kind — the frontend splits by kind)."""
    rows = await session.execute(
        select(EntityComment)
        .where(EntityComment.instance_id == instance_id)
        .order_by(EntityComment.kind, EntityComment.entity_key)
    )
    return list(rows.scalars().all())


async def list_all(session: AsyncSession, kind: str | None = None) -> list[EntityComment]:
    """Comments across ALL instances — the route scope-filters via its visible-id
    set (this function itself is unscoped; never expose it without that filter)."""
    stmt = select(EntityComment).order_by(EntityComment.instance_id, EntityComment.entity_key)
    if kind:
        stmt = stmt.where(EntityComment.kind == kind)
    rows = await session.execute(stmt)
    return list(rows.scalars().all())


async def upsert(
    session: AsyncSession,
    instance_id: int,
    kind: str,
    entity_key: str,
    comment: str,
    username: str,
) -> EntityComment:
    """Insert or update the (instance, kind, entity_key) comment. Flushes only."""
    row = (
        await session.execute(
            select(EntityComment).where(
                EntityComment.instance_id == instance_id,
                EntityComment.kind == kind,
                EntityComment.entity_key == entity_key,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = EntityComment(
            instance_id=instance_id,
            kind=kind,
            entity_key=entity_key,
            comment=comment,
            updated_by=username,
        )
        session.add(row)
    else:
        row.comment = comment
        row.updated_by = username
    await session.flush()
    return row


async def remove(session: AsyncSession, instance_id: int, kind: str, entity_key: str) -> bool:
    """Delete the (instance, kind, entity_key) comment; True when a row existed."""
    result = await session.execute(
        sa_delete(EntityComment).where(
            EntityComment.instance_id == instance_id,
            EntityComment.kind == kind,
            EntityComment.entity_key == entity_key,
        )
    )
    return bool(result.rowcount)
