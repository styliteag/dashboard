"""CRUD for read-only API keys (service accounts).

Admins and superadmins manage keys. Keys may be bound to instance groups
(``apikey_groups``): a bound key only reads its groups' instances; an unbound
key is global. A group-scoped admin must bind new keys to his own groups and
may reveal only keys bound within his groups — otherwise minting/reading a
global key would bypass his instance scoping. Binding is fixed at creation;
re-mint to change it. Losing a group membership later does not disable a key
(the binding lives on the key, not its creator) — it only removes reveal.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.apikey import generate_key
from app.auth.deps import require_admin_or_superadmin
from app.crypto.secrets import decrypt, encrypt
from app.db.base import get_session
from app.db.models import ApiKey, Group, User
from app.groups.schemas import GroupBrief
from app.net import client_ip

router = APIRouter(prefix="/apikeys", tags=["apikeys"])


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    # When True the full token is also kept Fernet-encrypted so it can be
    # re-displayed later (GET /apikeys/{id}/reveal). Default is show-once.
    revealable: bool = False
    # Group binding. None/empty = global key (superadmin only); a non-superadmin
    # admin MUST bind to a non-empty subset of his own groups.
    group_ids: list[int] | None = None
    # Optional purpose to organize keys by integration ("checkmk", "prometheus", …).
    # Purely for UI filtering in Settings; has no effect on auth or exports.
    purpose: str | None = None


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
    groups: list[GroupBrief]
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    purpose: str | None = None


class ApiKeyRevealed(BaseModel):
    id: int
    key: str


async def _resolve_binding(session: AsyncSession, user: User, group_ids: list[int] | None) -> list:
    """Validate + load the groups a new key gets bound to (see module docstring)."""
    ids = set(group_ids or [])
    if not user.is_superadmin:
        if not ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="a group-scoped admin must bind the key to at least one of his groups",
            )
        if not ids <= user.group_id_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="not a member of the target group(s)"
            )
    if not ids:
        return []
    groups = list((await session.execute(select(Group).where(Group.id.in_(ids)))).scalars().all())
    if len(groups) != len(ids):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown group")
    return groups


def _may_reveal(user: User, key: ApiKey) -> bool:
    """Superadmin: any key. Admin: only keys bound within his groups — a global
    key's token would bypass his instance scoping."""
    if user.is_superadmin:
        return True
    binding = key.group_id_set
    return bool(binding) and binding <= user.group_id_set


@router.post("", response_model=ApiKeyCreated)
async def create_apikey(
    payload: ApiKeyCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin_or_superadmin),
) -> ApiKeyCreated:
    groups = await _resolve_binding(session, user, payload.group_ids)
    token, key_hash, prefix = generate_key()
    key = ApiKey(
        name=payload.name,
        key_hash=key_hash,
        prefix=prefix,
        revealable=payload.revealable,
        key_enc=encrypt(token) if payload.revealable else None,
        purpose=payload.purpose,
        groups=groups,
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
        detail={
            "name": payload.name,
            "revealable": payload.revealable,
            "purpose": payload.purpose,
            "group_ids": sorted(g.id for g in groups),
        },
    )
    await session.commit()
    return ApiKeyCreated(id=key.id, name=key.name, prefix=prefix, key=token)


@router.get("", response_model=list[ApiKeyResponse])
async def list_apikeys(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(require_admin_or_superadmin),
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
    user: User = Depends(require_admin_or_superadmin),
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
    user: User = Depends(require_admin_or_superadmin),
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
    user: User = Depends(require_admin_or_superadmin),
) -> ApiKeyRevealed:
    """Return the full token of a revealable, non-revoked key (audited).

    Same 404 for missing / revoked / not-revealable / out-of-binding — no oracle.
    """
    key = await session.get(ApiKey, key_id)
    if (
        key is None
        or key.revoked_at is not None
        or not key.revealable
        or key.key_enc is None
        or not _may_reveal(user, key)
    ):
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
