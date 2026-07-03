"""SuperAdmin CRUD for dashboard user accounts (rights management).

SuperAdmin-only: user accounts, their global role, the superadmin flag and
group memberships are all rights management (admins lost this surface when
groups were introduced). Guards against lockout: the last admin can be neither
demoted nor deleted, the last superadmin can neither lose the flag nor be
deleted, and you cannot strip your own superadmin flag or delete yourself.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.bootstrap import admin_mode, superadmin_mode
from app.auth.deps import require_superadmin
from app.auth.roles import ROLE_ADMIN, Role
from app.auth.security import hash_password
from app.db.base import get_session
from app.db.models import Group, User, WebauthnCredential
from app.groups.schemas import GroupBrief
from app.net import client_ip

router = APIRouter(prefix="/users", tags=["users"])


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8)
    role: Role
    is_superadmin: bool = False
    group_ids: list[int] | None = None


class UserUpdate(BaseModel):
    role: Role | None = None
    new_password: str | None = Field(default=None, min_length=8)
    is_superadmin: bool | None = None
    # Replace-set semantics: None = unchanged, [] = remove all memberships.
    group_ids: list[int] | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    is_superadmin: bool
    groups: list[GroupBrief]
    created_at: datetime
    disabled: bool
    totp_enabled: bool


async def _admin_count(session: AsyncSession) -> int:
    return (
        await session.execute(select(func.count()).select_from(User).where(User.role == ROLE_ADMIN))
    ).scalar_one()


async def _superadmin_count(session: AsyncSession) -> int:
    return (
        await session.execute(
            select(func.count()).select_from(User).where(User.is_superadmin.is_(True))
        )
    ).scalar_one()


async def _retire_bootstrap_if_supplanted(session: AsyncSession) -> None:
    """Disable the password-only seed admin once a real admin exists.

    Skipped when the operator forces the seed on (DASH_ADMIN_DISABLED=0)."""
    if admin_mode() == "enabled":
        return
    boot = (
        await session.execute(
            select(User).where(
                User.is_bootstrap.is_(True),
                User.is_superadmin.is_(False),
                User.disabled.is_(False),
            )
        )
    ).scalar_one_or_none()
    if boot is not None:
        boot.disabled = True


async def _retire_superadmin_bootstrap_if_supplanted(session: AsyncSession) -> None:
    """Disable the seed superadmin once a real superadmin exists.

    Skipped when the operator forces the seed on (DASH_SUPERADMIN_DISABLED=0)."""
    if superadmin_mode() == "enabled":
        return
    boot = (
        await session.execute(
            select(User).where(
                User.is_bootstrap.is_(True),
                User.is_superadmin.is_(True),
                User.disabled.is_(False),
            )
        )
    ).scalar_one_or_none()
    if boot is not None:
        boot.disabled = True


async def _resolve_groups(session: AsyncSession, group_ids: list[int]) -> list[Group]:
    """Load the groups for a membership replace-set; unknown ids are a 400."""
    unique_ids = list(dict.fromkeys(group_ids))
    if not unique_ids:
        return []
    groups = list(
        (await session.execute(select(Group).where(Group.id.in_(unique_ids)))).scalars().all()
    )
    if len(groups) != len(unique_ids):
        found = {g.id for g in groups}
        missing = [i for i in unique_ids if i not in found]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"unknown group ids: {missing}"
        )
    return groups


@router.get("", response_model=list[UserOut])
async def list_users(
    session: AsyncSession = Depends(get_session),
    _actor: User = Depends(require_superadmin),
) -> list[User]:
    rows = (await session.execute(select(User).order_by(User.created_at.asc()))).scalars().all()
    return list(rows)


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    actor: User = Depends(require_superadmin),
) -> User:
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        password_version=1,
        role=payload.role,
        is_superadmin=payload.is_superadmin,
    )
    if payload.group_ids:
        user.groups = await _resolve_groups(session, payload.group_ids)
    session.add(user)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="username already exists"
        ) from exc
    if payload.role == ROLE_ADMIN:
        await _retire_bootstrap_if_supplanted(session)
    if payload.is_superadmin:
        await _retire_superadmin_bootstrap_if_supplanted(session)
    await write_audit(
        session,
        action="user.create",
        result="ok",
        user_id=actor.id,
        target_type="user",
        target_id=str(user.id),
        source_ip=client_ip(request),
        detail={
            "username": payload.username,
            "role": payload.role,
            "is_superadmin": payload.is_superadmin,
            "group_ids": payload.group_ids or [],
        },
    )
    await session.commit()
    # Re-populate server-defaults (created_at) expired by the commit before the
    # response_model serializes the row — async sessions can't lazy-load here.
    await session.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    actor: User = Depends(require_superadmin),
) -> User:
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if payload.role is not None and payload.role != ROLE_ADMIN and target.role == ROLE_ADMIN:
        if target.id == actor.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cannot demote your own admin account",
            )
        if await _admin_count(session) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="cannot demote the last admin"
            )

    if payload.is_superadmin is False and target.is_superadmin:
        if target.id == actor.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cannot revoke your own superadmin flag",
            )
        if await _superadmin_count(session) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="cannot revoke the last superadmin"
            )

    detail: dict[str, object] = {}
    if payload.role is not None:
        detail["role"] = payload.role
        target.role = payload.role
        if payload.role == ROLE_ADMIN and not target.is_bootstrap:
            await _retire_bootstrap_if_supplanted(session)
    if payload.is_superadmin is not None:
        detail["is_superadmin"] = payload.is_superadmin
        target.is_superadmin = payload.is_superadmin
        if payload.is_superadmin and not target.is_bootstrap:
            await _retire_superadmin_bootstrap_if_supplanted(session)
    if payload.group_ids is not None:
        target.groups = await _resolve_groups(session, payload.group_ids)
        detail["group_ids"] = payload.group_ids
    if payload.new_password is not None:
        target.password_hash = hash_password(payload.new_password)
        # Bump so the target's existing sessions are invalidated after a reset.
        target.password_version += 1
        detail["password_reset"] = True

    await write_audit(
        session,
        action="user.update",
        result="ok",
        user_id=actor.id,
        target_type="user",
        target_id=str(target.id),
        source_ip=client_ip(request),
        detail=detail,
    )
    await session.commit()
    await session.refresh(target)
    return target


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    actor: User = Depends(require_superadmin),
) -> None:
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if target.id == actor.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cannot delete your own account"
        )
    if target.role == ROLE_ADMIN and await _admin_count(session) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cannot delete the last admin"
        )
    if target.is_superadmin and await _superadmin_count(session) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cannot delete the last superadmin"
        )

    await session.delete(target)
    await write_audit(
        session,
        action="user.delete",
        result="ok",
        user_id=actor.id,
        target_type="user",
        target_id=str(user_id),
        source_ip=client_ip(request),
        detail={"username": target.username},
    )
    await session.commit()


@router.post("/{user_id}/reset-2fa", response_model=UserOut)
async def reset_2fa(
    user_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    actor: User = Depends(require_superadmin),
) -> User:
    """Clear a user's second factor (recovery for a lost authenticator/passkey).

    Wipes TOTP + all passkeys and bumps ``password_version`` so any live session
    dies; the user is forced to re-enroll 2FA on their next login.
    """
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    target.totp_enabled = False
    target.totp_secret_enc = None
    target.password_version += 1
    await session.execute(delete(WebauthnCredential).where(WebauthnCredential.user_id == target.id))
    await write_audit(
        session,
        action="user.reset_2fa",
        result="ok",
        user_id=actor.id,
        target_type="user",
        target_id=str(target.id),
        source_ip=client_ip(request),
    )
    await session.commit()
    await session.refresh(target)
    return target
