"""Admin CRUD for read-only API keys (service accounts)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.apikey import generate_key
from app.auth.deps import require_admin
from app.crypto.secrets import decrypt, encrypt
from app.db.base import get_session
from app.db.models import ApiKey, User
from app.net import client_ip

router = APIRouter(prefix="/apikeys", tags=["apikeys"])


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    # When True the full token is also kept Fernet-encrypted so it can be
    # re-displayed later (GET /apikeys/{id}/reveal). Default is show-once.
    revealable: bool = False


class ApiKeyCreated(BaseModel):
    id: int
    name: str
    prefix: str
    key: str  # full token — shown only once


class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    prefix: str
    revealable: bool
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiKeyRevealed(BaseModel):
    id: int
    key: str


@router.post("", response_model=ApiKeyCreated)
async def create_apikey(
    payload: ApiKeyCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin),
) -> ApiKeyCreated:
    token, key_hash, prefix = generate_key()
    key = ApiKey(
        name=payload.name,
        key_hash=key_hash,
        prefix=prefix,
        revealable=payload.revealable,
        key_enc=encrypt(token) if payload.revealable else None,
    )
    session.add(key)
    await session.flush()
    await write_audit(
        session,
        action="apikey.create",
        result="ok",
        user_id=user.id,
        target_type="apikey",
        target_id=str(key.id),
        source_ip=client_ip(request),
        detail={"name": payload.name, "revealable": payload.revealable},
    )
    await session.commit()
    return ApiKeyCreated(id=key.id, name=key.name, prefix=prefix, key=token)


@router.get("", response_model=list[ApiKeyResponse])
async def list_apikeys(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(require_admin),
) -> list[ApiKey]:
    rows = (
        (await session.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))).scalars().all()
    )
    return list(rows)


@router.delete("/{key_id}")
async def revoke_apikey(
    key_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin),
) -> dict:
    key = await session.get(ApiKey, key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
    # Drop the recoverable copy on revoke — a revoked key should not be revealable.
    key.key_enc = None
    await write_audit(
        session,
        action="apikey.revoke",
        result="ok",
        user_id=user.id,
        target_type="apikey",
        target_id=str(key_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return {"ok": True}


@router.delete("/{key_id}/purge")
async def delete_apikey(
    key_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin),
) -> dict:
    """Hard-delete a key row. Only a revoked key can be purged — an active key
    must be revoked first (revoke = soft, drops its recoverable copy; purge =
    remove the row entirely so it stops cluttering the list)."""
    key = await session.get(ApiKey, key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if key.revoked_at is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="revoke the key before deleting it",
        )
    await session.delete(key)
    await write_audit(
        session,
        action="apikey.delete",
        result="ok",
        user_id=user.id,
        target_type="apikey",
        target_id=str(key_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return {"ok": True}


@router.get("/{key_id}/reveal", response_model=ApiKeyRevealed)
async def reveal_apikey(
    key_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin),
) -> ApiKeyRevealed:
    """Return the full token of a revealable, non-revoked key (admin-only, audited)."""
    key = await session.get(ApiKey, key_id)
    if key is None or key.revoked_at is not None or not key.revealable or key.key_enc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not revealable")
    await write_audit(
        session,
        action="apikey.reveal",
        result="ok",
        user_id=user.id,
        target_type="apikey",
        target_id=str(key_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return ApiKeyRevealed(id=key.id, key=decrypt(key.key_enc))
