"""Second-factor endpoints — login step 2 and enrollment.

All routes here run on ``require_pending_mfa``: reachable only between a correct
password (login step 1) and a passed factor. On success they call
``complete_login`` to mint the real session. Failed codes feed the same IP
limiter as a bad password so the 6-digit step can't be brute-forced.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)

from app.audit.log import write_audit
from app.auth import totp, webauthn_svc
from app.auth.deps import current_user, require_pending_mfa
from app.auth.routes import UserResponse, complete_login
from app.auth.security import limiter
from app.config import get_settings
from app.crypto.secrets import decrypt, encrypt
from app.db.base import get_session
from app.db.models import User, WebauthnCredential
from app.net import client_ip

router = APIRouter(prefix="/auth/mfa", tags=["auth"])

_WA_CHALLENGE = "mfa_wa_challenge"


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


# --- WebAuthn / passkeys (login step 2 + enrollment) ----------------------


class WebauthnRegisterVerify(BaseModel):
    credential: dict[str, Any]
    name: str | None = Field(default=None, max_length=128)


class WebauthnAuthVerify(BaseModel):
    credential: dict[str, Any]


async def _user_credentials(session: AsyncSession, user: User) -> list[WebauthnCredential]:
    rows = await session.execute(
        select(WebauthnCredential).where(WebauthnCredential.user_id == user.id)
    )
    return list(rows.scalars().all())


def _options_response(request: Request, options_json: str, challenge: str) -> Response:
    request.session[_WA_CHALLENGE] = challenge
    return Response(content=options_json, media_type="application/json")


@router.post("/webauthn/register/options")
async def webauthn_register_options(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_pending_mfa)],
) -> Response:
    existing = await _user_credentials(session, user)
    options_json, challenge = webauthn_svc.registration_options(user.id, user.username, existing)
    return _options_response(request, options_json, challenge)


@router.post("/webauthn/register/verify", response_model=UserResponse)
async def webauthn_register_verify(
    payload: WebauthnRegisterVerify,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_pending_mfa)],
) -> UserResponse:
    """Finish passkey enrollment, then mint the session."""
    ip = client_ip(request)
    challenge = request.session.pop(_WA_CHALLENGE, None)
    if not challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no challenge")
    try:
        verified = webauthn_svc.verify_registration(
            payload.credential, base64url_to_bytes(challenge)
        )
    except InvalidRegistrationResponse as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="passkey registration failed"
        ) from exc
    transports = (payload.credential.get("response") or {}).get("transports") or []
    session.add(
        WebauthnCredential(
            user_id=user.id,
            credential_id=bytes_to_base64url(verified.credential_id),
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            name=payload.name,
            transports=",".join(transports)[:255] or None,
        )
    )
    return await complete_login(request, session, user, ip)


@router.post("/webauthn/auth/options")
async def webauthn_auth_options(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_pending_mfa)],
) -> Response:
    creds = await _user_credentials(session, user)
    if not creds:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no passkey enrolled")
    options_json, challenge = webauthn_svc.authentication_options(creds)
    return _options_response(request, options_json, challenge)


@router.post("/webauthn/auth/verify", response_model=UserResponse)
async def webauthn_auth_verify(
    payload: WebauthnAuthVerify,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(require_pending_mfa)],
) -> UserResponse:
    """Login step 2 with a passkey assertion."""
    ip = await _guard_rate(request)
    challenge = request.session.pop(_WA_CHALLENGE, None)
    if not challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no challenge")
    cred_id = payload.credential.get("id")
    cred = (
        await session.execute(
            select(WebauthnCredential).where(
                WebauthnCredential.user_id == user.id,
                WebauthnCredential.credential_id == cred_id,
            )
        )
    ).scalar_one_or_none()
    if cred is None:
        await _reject_passkey(session, user, ip)
    try:
        verified = webauthn_svc.verify_authentication(
            payload.credential, base64url_to_bytes(challenge), cred.public_key, cred.sign_count
        )
    except InvalidAuthenticationResponse:
        await _reject_passkey(session, user, ip)
    cred.sign_count = verified.new_sign_count
    cred.last_used_at = datetime.now(UTC)
    return await complete_login(request, session, user, ip)


async def _reject_passkey(session: AsyncSession, user: User, ip: str) -> None:
    triggered = limiter.record_failure(ip)
    await write_audit(
        session,
        action="auth.mfa_verify",
        result="error",
        user_id=user.id,
        detail={"reason": "passkey_failed", "lock_triggered": triggered},
        source_ip=ip,
    )
    await session.commit()
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="passkey verification failed"
    )


# --- Self-service 2FA management (logged in; any role manages its own) -----


class PasskeyInfo(BaseModel):
    id: int
    name: str | None
    created_at: datetime
    last_used_at: datetime | None


class MfaMethods(BaseModel):
    totp_enabled: bool
    passkeys: list[PasskeyInfo]


@router.get("/methods", response_model=MfaMethods)
async def my_methods(
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> MfaMethods:
    creds = await _user_credentials(session, user)
    return MfaMethods(
        totp_enabled=user.totp_enabled,
        passkeys=[
            PasskeyInfo(id=c.id, name=c.name, created_at=c.created_at, last_used_at=c.last_used_at)
            for c in creds
        ],
    )


@router.post("/webauthn/manage/options")
async def manage_register_options(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> Response:
    existing = await _user_credentials(session, user)
    options_json, challenge = webauthn_svc.registration_options(user.id, user.username, existing)
    return _options_response(request, options_json, challenge)


@router.post("/webauthn/manage/verify", response_model=PasskeyInfo)
async def manage_register_verify(
    payload: WebauthnRegisterVerify,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> PasskeyInfo:
    """Add a passkey to the signed-in account (no new session)."""
    challenge = request.session.pop(_WA_CHALLENGE, None)
    if not challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no challenge")
    try:
        verified = webauthn_svc.verify_registration(
            payload.credential, base64url_to_bytes(challenge)
        )
    except InvalidRegistrationResponse as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="passkey registration failed"
        ) from exc
    transports = (payload.credential.get("response") or {}).get("transports") or []
    cred = WebauthnCredential(
        user_id=user.id,
        credential_id=bytes_to_base64url(verified.credential_id),
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        name=payload.name,
        transports=",".join(transports)[:255] or None,
    )
    session.add(cred)
    await write_audit(
        session,
        action="auth.mfa_passkey_add",
        result="ok",
        user_id=user.id,
        source_ip=client_ip(request),
    )
    await session.commit()
    await session.refresh(cred)
    return PasskeyInfo(
        id=cred.id, name=cred.name, created_at=cred.created_at, last_used_at=cred.last_used_at
    )


@router.delete("/passkeys/{cred_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_passkey(
    cred_id: int,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    user: Annotated[User, Depends(current_user)],
) -> None:
    """Remove a passkey — but never the account's last remaining second factor."""
    cred = await session.get(WebauthnCredential, cred_id)
    if cred is None or cred.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    others = await _user_credentials(session, user)
    if not user.totp_enabled and len(others) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cannot remove your only second factor",
        )
    await session.delete(cred)
    await write_audit(
        session,
        action="auth.mfa_passkey_remove",
        result="ok",
        user_id=user.id,
        target_id=str(cred_id),
        source_ip=client_ip(request),
    )
    await session.commit()
