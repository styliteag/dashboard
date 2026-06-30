"""Auth endpoints — login, logout, me, change-password.

Closes US-1.1, US-1.2, US-1.3, US-1.4.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import current_user
from app.auth.dev_token import issue_dev_token
from app.auth.security import hash_password, limiter, verify_password, verify_password_constant_time
from app.config import get_settings
from app.db.base import get_session
from app.db.models import User, WebauthnCredential
from app.net import client_ip

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8)


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    is_admin: bool
    session_token: str | None = None


class LoginChallenge(BaseModel):
    """Step-1 result: password accepted, second factor still required.

    ``stage`` is ``"verify"`` when the account already has a factor enrolled, or
    ``"enroll"`` when mandatory 2FA setup must happen before a session is minted.
    """

    stage: str
    totp: bool
    webauthn: bool


async def user_factor_state(session: AsyncSession, user: User) -> tuple[bool, bool]:
    """(totp_enrolled, has_passkey) for the given user."""
    totp_on = bool(user.totp_enabled and user.totp_secret_enc is not None)
    passkeys = await session.scalar(
        select(func.count())
        .select_from(WebauthnCredential)
        .where(WebauthnCredential.user_id == user.id)
    )
    return totp_on, bool(passkeys)


async def complete_login(
    request: Request, session: AsyncSession, user: User, ip: str
) -> UserResponse:
    """Mint a fully-authenticated session once the second factor has passed."""
    limiter.record_success(ip)
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["password_version"] = user.password_version
    request.session["mfa_passed"] = True
    await write_audit(session, action="auth.login", result="ok", user_id=user.id, source_ip=ip)
    await session.commit()
    token = issue_dev_token(user.id, user.password_version) if get_settings().env == "dev" else None
    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        is_admin=user.is_admin,
        session_token=token,
    )


@router.post("/login", response_model=LoginChallenge)
async def login(
    payload: LoginRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> LoginChallenge:
    """Step 1 of login: verify the password, then hand off to the second factor.

    A correct password never mints a session on its own — it stores a *pending*
    state and returns a challenge. The session is minted only by the matching
    ``/auth/mfa/*`` endpoint once TOTP or a passkey passes.
    """
    ip = client_ip(request)

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

    # Always pay one Argon2 verify (dummy hash when the user is absent) so login
    # latency can't be used to enumerate valid usernames.
    if not verify_password_constant_time(payload.password, user.password_hash if user else None):
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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    if user.disabled:
        await write_audit(
            session,
            action="auth.login",
            result="denied",
            user_id=user.id,
            detail={"reason": "account_disabled"},
            source_ip=ip,
        )
        await session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="account disabled")

    # Password OK → enter the pending-MFA state (no real session yet).
    request.session.clear()
    request.session["mfa_user_id"] = user.id
    request.session["mfa_pw_version"] = user.password_version

    totp_on, webauthn_on = await user_factor_state(session, user)
    stage = "verify" if (totp_on or webauthn_on) else "enroll"
    await write_audit(
        session,
        action="auth.login",
        result="pending",
        user_id=user.id,
        detail={"stage": stage},
        source_ip=ip,
    )
    await session.commit()
    return LoginChallenge(stage=stage, totp=totp_on, webauthn=webauthn_on)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> None:
    request.session.clear()
    await write_audit(
        session, action="auth.logout", result="ok", user_id=user.id, source_ip=client_ip(request)
    )
    await session.commit()


@router.get("/me", response_model=UserResponse)
async def me(user: Annotated[User, Depends(current_user)]) -> UserResponse:
    return UserResponse(id=user.id, username=user.username, role=user.role, is_admin=user.is_admin)


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
            source_ip=client_ip(request),
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
        source_ip=client_ip(request),
    )
    await session.commit()
    return UserResponse(id=user.id, username=user.username, role=user.role, is_admin=user.is_admin)
