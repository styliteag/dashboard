"""Admin CRUD for dashboard user accounts (role management).

Admin-only. Guards against lockout: the last admin can be neither demoted nor
deleted, and you cannot demote or delete your own admin account.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_admin
from app.auth.roles import ROLE_ADMIN, Role
from app.auth.security import hash_password
from app.db.base import get_session
from app.db.models import User
from app.net import client_ip

router = APIRouter(prefix="/users", tags=["users"])


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=12)
    role: Role


class UserUpdate(BaseModel):
    role: Role | None = None
    new_password: str | None = Field(default=None, min_length=12)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    created_at: datetime


async def _admin_count(session: AsyncSession) -> int:
    return (
        await session.execute(select(func.count()).select_from(User).where(User.role == ROLE_ADMIN))
    ).scalar_one()


@router.get("", response_model=list[UserOut])
async def list_users(
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> list[User]:
    rows = (await session.execute(select(User).order_by(User.created_at.asc()))).scalars().all()
    return list(rows)


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> User:
    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        password_version=1,
        role=payload.role,
    )
    session.add(user)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="username already exists"
        ) from exc
    await write_audit(
        session,
        action="user.create",
        result="ok",
        user_id=admin.id,
        target_type="user",
        target_id=str(user.id),
        source_ip=client_ip(request),
        detail={"username": payload.username, "role": payload.role},
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
    admin: User = Depends(require_admin),
) -> User:
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if payload.role is not None and payload.role != ROLE_ADMIN and target.role == ROLE_ADMIN:
        if target.id == admin.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cannot demote your own admin account",
            )
        if await _admin_count(session) <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="cannot demote the last admin"
            )

    detail: dict[str, object] = {}
    if payload.role is not None:
        detail["role"] = payload.role
        target.role = payload.role
    if payload.new_password is not None:
        target.password_hash = hash_password(payload.new_password)
        # Bump so the target's existing sessions are invalidated after an admin reset.
        target.password_version += 1
        detail["password_reset"] = True

    await write_audit(
        session,
        action="user.update",
        result="ok",
        user_id=admin.id,
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
    admin: User = Depends(require_admin),
) -> None:
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if target.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cannot delete your own account"
        )
    if target.role == ROLE_ADMIN and await _admin_count(session) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cannot delete the last admin"
        )

    await session.delete(target)
    await write_audit(
        session,
        action="user.delete",
        result="ok",
        user_id=admin.id,
        target_type="user",
        target_id=str(user_id),
        source_ip=client_ip(request),
        detail={"username": target.username},
    )
    await session.commit()
