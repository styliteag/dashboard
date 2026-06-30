"""Second-factor endpoints — login step 2 and enrollment.

All routes here run on ``require_pending_mfa``: reachable only between a correct
password (login step 1) and a passed factor. On success they call
``complete_login`` to mint the real session. Failed codes feed the same IP
limiter as a bad password so the 6-digit step can't be brute-forced.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth import totp
from app.auth.deps import require_pending_mfa
from app.auth.routes import UserResponse, complete_login
from app.auth.security import limiter
from app.config import get_settings
from app.crypto.secrets import decrypt, encrypt
from app.db.base import get_session
from app.db.models import User
from app.net import client_ip

router = APIRouter(prefix="/auth/mfa", tags=["auth"])


class TotpSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


async def _guard_rate(request: Request) -> str:
    ip = client_ip(request)
    if limiter.is_locked(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many failed attempts; try again later",
        )
    return ip


async def _reject_code(session: AsyncSession, user: User, ip: str, action: str) -> None:
    triggered = limiter.record_failure(ip)
    await write_audit(
        session,
        action=action,
        result="error",
        user_id=user.id,
        detail={"reason": "invalid_code", "lock_triggered": triggered},
        source_ip=ip,
    )
    await session.commit()
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid code")


@router.post("/setup/totp", response_model=TotpSetupResponse)
async def setup_totp(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_pending_mfa)],
) -> TotpSetupResponse:
    """Generate a fresh TOTP secret for enrollment (not yet enabled).

    The secret is stored encrypted with ``totp_enabled`` still False — it only
    becomes a usable factor after ``/confirm/totp`` echoes a valid code.
    """
    secret = totp.generate_secret()
    user.totp_secret_enc = encrypt(secret)
    user.totp_enabled = False
    await session.commit()
    uri = totp.provisioning_uri(secret, account=user.username, issuer=get_settings().mfa_issuer)
    return TotpSetupResponse(secret=secret, otpauth_uri=uri)


@router.post("/confirm/totp", response_model=UserResponse)
async def confirm_totp(
    payload: CodeRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_pending_mfa)],
) -> UserResponse:
    """Finish enrollment: verify the first code, enable TOTP, mint the session."""
    ip = await _guard_rate(request)
    if user.totp_secret_enc is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="no enrollment in progress"
        )
    secret = decrypt(user.totp_secret_enc)
    if not totp.verify(secret, payload.code):
        await _reject_code(session, user, ip, "auth.mfa_confirm")
    user.totp_enabled = True
    return await complete_login(request, session, user, ip)


@router.post("/verify/totp", response_model=UserResponse)
async def verify_totp(
    payload: CodeRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_pending_mfa)],
) -> UserResponse:
    """Login step 2 for an already-enrolled user."""
    ip = await _guard_rate(request)
    if not user.totp_enabled or user.totp_secret_enc is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="TOTP not enrolled")
    secret = decrypt(user.totp_secret_enc)
    if not totp.verify(secret, payload.code):
        await _reject_code(session, user, ip, "auth.mfa_verify")
    return await complete_login(request, session, user, ip)
