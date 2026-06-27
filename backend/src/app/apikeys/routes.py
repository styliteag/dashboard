"""Admin CRUD for read-only API keys (service accounts)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.apikey import generate_key
from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import ApiKey, User
from app.net import client_ip

router = APIRouter(prefix="/apikeys", tags=["apikeys"])


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)


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
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


@router.post("", response_model=ApiKeyCreated)
async def create_apikey(
    payload: ApiKeyCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> ApiKeyCreated:
    token, key_hash, prefix = generate_key()
    key = ApiKey(name=payload.name, key_hash=key_hash, prefix=prefix)
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
        detail={"name": payload.name},
    )
    await session.commit()
    return ApiKeyCreated(id=key.id, name=key.name, prefix=prefix, key=token)


@router.get("", response_model=list[ApiKeyResponse])
async def list_apikeys(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
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
    user: User = Depends(current_user),
) -> dict:
    key = await session.get(ApiKey, key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if key.revoked_at is None:
        key.revoked_at = datetime.now(UTC)
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
