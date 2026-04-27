"""Auth endpoints — login, logout, me, change-password.

Closes US-1.1, US-1.2, US-1.3, US-1.4.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import current_user
from app.auth.dev_token import issue_dev_token
from app.auth.security import hash_password, limiter, verify_password
from app.config import get_settings
from app.db.base import get_session
from app.db.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=12)


class UserResponse(BaseModel):
    id: int
    username: str
    is_admin: bool
    session_token: str | None = None


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=UserResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> UserResponse:
    ip = _client_ip(request)

    if limiter.is_locked(ip):
        await write_audit(
            session,
            action="auth.login",
            result="denied",
            detail={"reason": "ip_locked", "username": payload.username},
            source_ip=ip,
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many failed attempts; try again later",
        )

    user = (
        await session.execute(select(User).where(User.username == payload.username))
    ).scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.password_hash):
        triggered_lock = limiter.record_failure(ip)
        await write_audit(
            session,
            action="auth.login",
            result="error",
            detail={
                "reason": "bad_credentials",
                "username": payload.username,
                "lock_triggered": triggered_lock,
            },
            source_ip=ip,
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
        )

    limiter.record_success(ip)
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["password_version"] = user.password_version

    await write_audit(
        session,
        action="auth.login",
        result="ok",
        user_id=user.id,
        source_ip=ip,
    )
    await session.commit()
    token = issue_dev_token(user.id, user.password_version) if get_settings().env == "dev" else None
    return UserResponse(
        id=user.id, username=user.username, is_admin=user.is_admin, session_token=token
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> None:
    request.session.clear()
    await write_audit(
        session, action="auth.logout", result="ok", user_id=user.id, source_ip=_client_ip(request)
    )
    await session.commit()


@router.get("/me", response_model=UserResponse)
async def me(user: Annotated[User, Depends(current_user)]) -> UserResponse:
    return UserResponse(id=user.id, username=user.username, is_admin=user.is_admin)


@router.post("/password", response_model=UserResponse)
async def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> UserResponse:
    if not verify_password(payload.old_password, user.password_hash):
        await write_audit(
            session,
            action="auth.password_change",
            result="error",
            user_id=user.id,
            source_ip=_client_ip(request),
            detail={"reason": "bad_old_password"},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="old password incorrect"
        )

    user.password_hash = hash_password(payload.new_password)
    user.password_version += 1  # invalidates all other sessions

    # Re-issue *this* session with the new version so the current client stays logged in.
    request.session["password_version"] = user.password_version

    await write_audit(
        session,
        action="auth.password_change",
        result="ok",
        user_id=user.id,
        source_ip=_client_ip(request),
    )
    await session.commit()
    return UserResponse(id=user.id, username=user.username, is_admin=user.is_admin)
