"""Per-group notification-channel config API.

A configured group channel REPLACES the global target for that group's
instances (see app.notifications.notifier); deleting it falls back to the
global channel. Managed by superadmins and by admins for groups they are
member of — a non-member gets 404 (invisible, not forbidden). Field shapes,
secret flags and the mask convention live in app.notifications.channel_config.
"""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_admin_or_superadmin
from app.crypto.secrets import decrypt, encrypt
from app.db.base import get_session
from app.db.models import Group, GroupChannel, User
from app.net import client_ip
from app.notifications.channel_config import CHANNEL_FIELDS, CHANNELS, MASK
from app.notifications.notifier import _ssrf_block_reason

router = APIRouter(prefix="/groups", tags=["groups"])


class GroupChannelOut(BaseModel):
    channel: str
    config: dict[str, str]  # secrets replaced by MASK
    updated_at: datetime


class GroupChannelPut(BaseModel):
    # Full replace; a secret field equal to MASK keeps the stored value.
    config: dict[str, str]


async def _group_for(session: AsyncSession, group_id: int, user: User) -> Group:
    """Load the group; non-superadmins must be a member (404 otherwise)."""
    group = await session.get(Group, group_id)
    if group is None or (not user.is_superadmin and group_id not in user.group_id_set):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return group


def _masked(channel: str, config: dict[str, str]) -> dict[str, str]:
    fields = {f.name: f for f in CHANNEL_FIELDS[channel]}
    return {
        name: (MASK if fields[name].secret and value else value)
        for name, value in config.items()
        if name in fields
    }


async def _validated_config(
    channel: str, incoming: dict[str, str], existing: dict[str, str]
) -> dict[str, str]:
    """Validate a full-replace payload against the channel's field spec.

    Unknown fields are rejected; a secret sent as MASK keeps the stored value;
    required fields must end up non-empty. Mattermost URLs are SSRF-checked at
    save time (the sender re-checks at send time as defense in depth).
    """
    fields = {f.name: f for f in CHANNEL_FIELDS[channel]}
    unknown = sorted(set(incoming) - set(fields))
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"unknown fields: {unknown}"
        )
    config: dict[str, str] = {}
    for name, field in fields.items():
        value = str(incoming.get(name, "") or "").strip()
        if field.secret and value == MASK:
            value = existing.get(name, "")
        if field.required and not value:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"field '{name}' is required",
            )
        if value and field.options and value not in field.options:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"field '{name}' must be one of {list(field.options)}",
            )
        config[name] = value
    if channel == "email" and config.get("smtp_port"):
        try:
            port = int(config["smtp_port"])
        except ValueError:
            port = 0
        if not 1 <= port <= 65535:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="invalid smtp_port"
            )
    if channel == "mattermost":
        reason = await _ssrf_block_reason(config["url"])
        if reason:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"URL rejected: {reason}"
            )
    return config


def _require_channel(channel: str) -> str:
    if channel not in CHANNELS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown channel")
    return channel


async def _get_row(session: AsyncSession, group_id: int, channel: str) -> GroupChannel | None:
    return (
        await session.execute(
            select(GroupChannel).where(
                GroupChannel.group_id == group_id, GroupChannel.channel == channel
            )
        )
    ).scalar_one_or_none()


@router.get("/{group_id}/channels", response_model=list[GroupChannelOut])
async def list_group_channels(
    group_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin_or_superadmin),
) -> list[GroupChannelOut]:
    await _group_for(session, group_id, user)
    rows = (
        (
            await session.execute(
                select(GroupChannel)
                .where(GroupChannel.group_id == group_id)
                .order_by(GroupChannel.channel)
            )
        )
        .scalars()
        .all()
    )
    return [
        GroupChannelOut(
            channel=r.channel,
            config=_masked(r.channel, json.loads(decrypt(r.config_enc))),
            updated_at=r.updated_at,
        )
        for r in rows
    ]


@router.put("/{group_id}/channels/{channel}", response_model=GroupChannelOut)
async def set_group_channel(
    group_id: int,
    channel: str,
    payload: GroupChannelPut,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin_or_superadmin),
) -> GroupChannelOut:
    _require_channel(channel)
    await _group_for(session, group_id, user)
    row = await _get_row(session, group_id, channel)
    existing = json.loads(decrypt(row.config_enc)) if row is not None else {}
    config = await _validated_config(channel, payload.config, existing)
    blob = encrypt(json.dumps(config))
    if row is None:
        row = GroupChannel(group_id=group_id, channel=channel, config_enc=blob)
        session.add(row)
    else:
        row.config_enc = blob
    await write_audit(
        session,
        action="group.channel.set",
        result="ok",
        user_id=user.id,
        target_type="group",
        target_id=str(group_id),
        source_ip=client_ip(request),
        detail={"channel": channel, "fields": sorted(k for k, v in config.items() if v)},
    )
    await session.commit()
    await session.refresh(row)
    return GroupChannelOut(
        channel=channel, config=_masked(channel, config), updated_at=row.updated_at
    )


@router.delete("/{group_id}/channels/{channel}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_group_channel(
    group_id: int,
    channel: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin_or_superadmin),
) -> None:
    _require_channel(channel)
    await _group_for(session, group_id, user)
    row = await _get_row(session, group_id, channel)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not configured")
    await session.delete(row)
    await write_audit(
        session,
        action="group.channel.delete",
        result="ok",
        user_id=user.id,
        target_type="group",
        target_id=str(group_id),
        source_ip=client_ip(request),
        detail={"channel": channel},
    )
    await session.commit()
