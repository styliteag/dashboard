"""SuperAdmin CRUD for instance groups.

Groups are pure instance containers: every instance belongs to exactly one and
users only see instances of groups they are member of (see app.auth.scope).
Managed exclusively by superadmins. Deleting a group requires it to be empty —
soft-deleted instances count too (the DB FK is ON DELETE RESTRICT); move them
first. Memberships are removed with the group (CASCADE).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_superadmin
from app.db.base import get_session
from app.db.models import Group, Instance, User, user_groups
from app.groups.schemas import GroupCreate, GroupInstanceOut, GroupOut, GroupUpdate
from app.net import client_ip

router = APIRouter(prefix="/groups", tags=["groups"])


async def _get_group(session: AsyncSession, group_id: int) -> Group:
    group = await session.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return group


@router.get("", response_model=list[GroupOut])
async def list_groups(
    session: AsyncSession = Depends(get_session),
    _actor: User = Depends(require_superadmin),
) -> list[GroupOut]:
    groups = (await session.execute(select(Group).order_by(Group.name))).scalars().all()
    members = dict(
        (
            await session.execute(
                select(user_groups.c.group_id, func.count()).group_by(user_groups.c.group_id)
            )
        ).all()
    )
    # Active instances only in the displayed count; the delete guard below also
    # counts soft-deleted rows (they still hold the FK).
    instances = dict(
        (
            await session.execute(
                select(Instance.group_id, func.count())
                .where(Instance.deleted_at.is_(None))
                .group_by(Instance.group_id)
            )
        ).all()
    )
    return [
        GroupOut(
            id=g.id,
            name=g.name,
            created_at=g.created_at,
            member_count=members.get(g.id, 0),
            instance_count=instances.get(g.id, 0),
        )
        for g in groups
    ]


@router.post("", response_model=GroupOut, status_code=status.HTTP_201_CREATED)
async def create_group(
    payload: GroupCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    actor: User = Depends(require_superadmin),
) -> GroupOut:
    group = Group(name=payload.name)
    session.add(group)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="group name already exists"
        ) from exc
    await write_audit(
        session,
        action="group.create",
        result="ok",
        user_id=actor.id,
        target_type="group",
        target_id=str(group.id),
        source_ip=client_ip(request),
        detail={"name": payload.name},
    )
    await session.commit()
    await session.refresh(group)
    return GroupOut(
        id=group.id, name=group.name, created_at=group.created_at, member_count=0, instance_count=0
    )


@router.patch("/{group_id}", response_model=GroupOut)
async def rename_group(
    group_id: int,
    payload: GroupUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    actor: User = Depends(require_superadmin),
) -> GroupOut:
    group = await _get_group(session, group_id)
    old_name = group.name
    group.name = payload.name
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="group name already exists"
        ) from exc
    await write_audit(
        session,
        action="group.update",
        result="ok",
        user_id=actor.id,
        target_type="group",
        target_id=str(group.id),
        source_ip=client_ip(request),
        detail={"name": payload.name, "old_name": old_name},
    )
    await session.commit()
    await session.refresh(group)
    member_count = await session.scalar(
        select(func.count()).select_from(user_groups).where(user_groups.c.group_id == group.id)
    )
    instance_count = await session.scalar(
        select(func.count())
        .select_from(Instance)
        .where(Instance.group_id == group.id, Instance.deleted_at.is_(None))
    )
    return GroupOut(
        id=group.id,
        name=group.name,
        created_at=group.created_at,
        member_count=member_count or 0,
        instance_count=instance_count or 0,
    )


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group(
    group_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    actor: User = Depends(require_superadmin),
) -> None:
    group = await _get_group(session, group_id)
    # Count ALL rows (incl. soft-deleted): they still hold the FK and the DB
    # would refuse the delete anyway (ON DELETE RESTRICT).
    instance_count = await session.scalar(
        select(func.count()).select_from(Instance).where(Instance.group_id == group.id)
    )
    if instance_count:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="group still contains instances (including soft-deleted) — move them first",
        )
    await session.delete(group)
    await write_audit(
        session,
        action="group.delete",
        result="ok",
        user_id=actor.id,
        target_type="group",
        target_id=str(group_id),
        source_ip=client_ip(request),
        detail={"name": group.name},
    )
    await session.commit()


@router.get("/{group_id}/instances", response_model=list[GroupInstanceOut])
async def list_group_instances(
    group_id: int,
    session: AsyncSession = Depends(get_session),
    _actor: User = Depends(require_superadmin),
) -> list[Instance]:
    await _get_group(session, group_id)
    rows = (
        (
            await session.execute(
                select(Instance)
                .where(Instance.group_id == group_id, Instance.deleted_at.is_(None))
                .order_by(Instance.name)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)
