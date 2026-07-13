"""Auth endpoints — login, logout, me, change-password.

Closes US-1.1, US-1.2, US-1.3, US-1.4.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.access import store as access_store
from app.audit.log import write_audit
from app.auth.deps import current_user
from app.auth.dev_token import issue_dev_token
from app.auth.security import hash_password, limiter, verify_password, verify_password_constant_time
from app.config import get_settings
from app.db.base import get_session
from app.db.models import User, WebauthnCredential
from app.geoip import lookup as geoip_lookup
from app.groups.schemas import GroupBrief
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
    is_superadmin: bool
    groups: list[GroupBrief]
    session_token: str | None = None
    # Filled only by /auth/me (footer display, DR-G7); None in login responses.
    client_ip: str | None = None
    client_country: str | None = None


def _user_response(user: User, session_token: str | None = None) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        is_admin=user.is_admin,
        is_superadmin=user.is_superadmin,
        groups=[GroupBrief.model_validate(g) for g in user.groups],
        session_token=session_token,
    )


class LoginChallenge(BaseModel):
    """Step-1 result.

    ``stage`` is ``"verify"`` when the account already has a factor enrolled,
    ``"enroll"`` when mandatory 2FA setup must happen first, or ``"done"`` when the
    session is already minted — the password-only bootstrap admin, which is exempt
    from 2FA. On ``"done"`` the user is attached.
    """

    stage: str
    totp: bool
    webauthn: bool
    user: UserResponse | None = None


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
    # Session-registry row (DR-AL3, bookkeeping only): the sid in the cookie
    # correlates requests to this row for last_seen stamping and logout/expiry.
    sid = access_store.new_sid()
    request.session["sid"] = sid
    await access_store.open_session(session, sid=sid, user_id=user.id, ip=ip)
    # Last successful login (DR-G7): recorded only here — the password step
    # never mints a session, so it never counts as a login.
    user.last_login_ip = ip
    user.last_login_country = geoip_lookup.country_for(ip)
    user.last_login_at = datetime.now(UTC)
    await write_audit(session, action="auth.login", result="ok", user_id=user.id, source_ip=ip)
    await session.commit()
    token = issue_dev_token(user.id, user.password_version) if get_settings().env == "dev" else None
    return _user_response(user, session_token=token)


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

    # The bootstrap seed admin is password-only (no 2FA) — mint the session now.
    if user.is_bootstrap:
        me = await complete_login(request, session, user, ip)
        return LoginChallenge(stage="done", totp=False, webauthn=False, user=me)

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
    await access_store.close_session(session, request.session.get("sid"), "logout")
    request.session.clear()
    await write_audit(
        session, action="auth.logout", result="ok", user_id=user.id, source_ip=client_ip(request)
    )
    await session.commit()


@router.get("/me", response_model=UserResponse)
async def me(request: Request, user: Annotated[User, Depends(current_user)]) -> UserResponse:
    # The footer shows the caller their own IP (+country when resolvable) —
    # DR-G7 visibility; also the quickest way to debug geo lockout reports.
    response = _user_response(user)
    ip = client_ip(request)
    response.client_ip = ip
    response.client_country = geoip_lookup.country_for(ip)
    return response


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
    return _user_response(user)
