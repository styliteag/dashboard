"""REST endpoints for OPNsense instance management.

Closes US-2.1, US-2.2, US-2.3, US-2.4, US-2.5.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub import gui_caddy
from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_admin_or_superadmin, require_write
from app.config import get_settings
from app.db.base import get_session
from app.db.models import Group, Instance, User
from app.instances import service
from app.instances.schemas import (
    InstanceCreate,
    InstanceResponse,
    InstanceUpdate,
    TestConnectionResponse,
    instance_response,
)
from app.net import client_ip
from app.settings.store import effective_settings

router = APIRouter(prefix="/instances", tags=["instances"])

# Fields safe to record verbatim in the audit trail. An allowlist (not a denylist)
# so a newly-added secret field can never leak into the permanent audit log by
# default — which is exactly how ssh_key slipped past the old {"api_key",
# "api_secret"} denylist.
_SAFE_AUDIT_FIELDS = {
    "name",
    "slug",
    "base_url",
    "ssl_verify",
    "gui_login_enabled",
    "shell_enabled",
    "poll_interval_seconds",
    "push_interval_seconds",
    "ssh_enabled",
    "ssh_port",
    "ssh_user",
    "location",
    "notes",
    "tags",
    "ping_url",
    "maintenance",
    "firmware_locked",
}
# Secret-bearing fields: never logged by value, only recorded by name when rotated.
# (ca_bundle is a public cert but is kept out of the detail to stay small/uniform.)
_SECRET_AUDIT_FIELDS = {"api_key", "api_secret", "ssh_key", "ca_bundle"}


def _safe_audit_detail(payload: InstanceUpdate) -> dict:
    """Build an audit ``detail`` that can never carry a secret value.

    Only allowlisted fields are emitted verbatim; rotated secrets are recorded by
    name only (``secrets_rotated``), gated on a truthy value so a ``""`` ("keep
    existing") is not falsely logged as a rotation.
    """
    detail = payload.model_dump(mode="json", exclude_none=True, include=_SAFE_AUDIT_FIELDS)
    rotated = sorted(
        name for name in _SECRET_AUDIT_FIELDS & payload.model_fields_set if getattr(payload, name)
    )
    if rotated:
        detail["secrets_rotated"] = rotated
    return detail


@router.get("", response_model=list[InstanceResponse])
async def list_all(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[InstanceResponse]:
    rows = await service.list_instances(session, user)
    settings = effective_settings()
    now = datetime.now(UTC)
    resps = [instance_response(inst, settings, now) for inst in rows]
    # Layer console-password-protected flag from live hub status (agent push) when present.
    # Direct-poll and older snapshots default to None (no warning).
    enriched: list[InstanceResponse] = []
    for r in resps:
        if r.agent_mode:
            st = hub.get_last_status(r.id)  # type: ignore[attr-defined]
            if st is not None and getattr(st, "console_password_protected", None):
                cp = bool(st.console_password_protected)
                enriched.append(r.model_copy(update={"console_password_protected": cp}))
            else:
                enriched.append(r)
        else:
            enriched.append(r)
    return enriched


async def _resolve_create_group(session: AsyncSession, user: User, group_id: int | None) -> int:
    """Target group for a new instance: one of the creator's groups (superadmins
    may target any existing group); implied when the user has exactly one."""
    memberships = user.group_id_set
    if group_id is None:
        if len(memberships) == 1:
            return next(iter(memberships))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="group_id required (you are not a member of exactly one group)",
        )
    if user.is_superadmin:
        if await session.get(Group, group_id) is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown group")
        return group_id
    if group_id not in memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="not a member of the target group"
        )
    return group_id


@router.post("", response_model=InstanceResponse, status_code=status.HTTP_201_CREATED)
async def create(
    payload: InstanceCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> Instance:
    group_id = await _resolve_create_group(session, user, payload.group_id)
    try:
        inst = await service.create_instance(session, payload, group_id)
    except service.SlugConflictError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="instance name or slug already exists"
        ) from exc
    await write_audit(
        session,
        action="instance.create",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=inst.id,
        source_ip=client_ip(request),
        detail={"name": inst.name},
    )
    await session.commit()
    await session.refresh(inst)
    await gui_caddy.reconcile(session)  # add this instance's vhost to the GUI proxy
    return inst


@router.get("/defaults")
async def interval_defaults(_user: User = Depends(current_user)) -> dict:
    """Global interval defaults so the UI can show what an empty override inherits.

    Declared before ``/{instance_id}`` so the literal path wins the match.
    """
    s = get_settings()
    return {
        "poll_interval_seconds": s.poll_interval_seconds,
        "push_interval_seconds": s.push_interval_seconds,
        "poll_tick_seconds": s.poll_tick_seconds,
    }


@router.get("/{instance_id}", response_model=InstanceResponse)
async def get(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> InstanceResponse:
    inst = await service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    resp = instance_response(inst, effective_settings(), datetime.now(UTC))
    if resp.agent_mode:
        st = hub.get_last_status(resp.id)  # type: ignore[attr-defined]
        if st is not None and getattr(st, "console_password_protected", None):
            cp = bool(st.console_password_protected)
            resp = resp.model_copy(update={"console_password_protected": cp})
    return resp


@router.patch("/{instance_id}", response_model=InstanceResponse)
async def update(
    instance_id: int,
    payload: InstanceUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> Instance:
    inst = await service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    # Arming a box's root shell has real blast radius — gate that one field on
    # admin, above the write role the rest of the update needs.
    if "shell_enabled" in payload.model_fields_set and not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin role required to change terminal access",
        )
    try:
        await service.update_instance(session, inst, payload)
    except service.SlugConflictError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="instance name or slug already exists"
        ) from exc
    await write_audit(
        session,
        action="instance.update",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=inst.id,
        source_ip=client_ip(request),
        detail=_safe_audit_detail(payload),
    )
    await session.commit()
    await session.refresh(inst)
    # Live-apply a changed push cadence to a connected agent; otherwise it only
    # picks the new value up from the welcome frame on the next reconnect.
    if "push_interval_seconds" in payload.model_fields_set and inst.agent_mode:
        agent = hub.get(inst.id)
        if agent is not None:
            await agent.send_config(
                push_interval=inst.push_interval_seconds or get_settings().push_interval_seconds
            )
    await gui_caddy.reconcile(session)  # reflect a possible slug change
    return inst


@router.delete("/{instance_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> None:
    inst = await service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    await service.soft_delete_instance(session, inst)
    await write_audit(
        session,
        action="instance.delete",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=inst.id,
        source_ip=client_ip(request),
        detail={"name": inst.name},
    )
    await session.commit()
    await gui_caddy.reconcile(session)  # drop this instance's vhost from the GUI proxy


@router.post("/{instance_id}/test", response_model=TestConnectionResponse)
async def test(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> TestConnectionResponse:
    inst = await service.get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    if inst.agent_mode:
        agent = hub.get(inst.id)
        if agent is None:
            ok, latency_ms, error = False, None, "agent not connected"
        else:
            t0 = time.monotonic()
            result = await agent.send_command("ping", timeout=10.0)
            latency_ms = int((time.monotonic() - t0) * 1000)
            ok = result.get("success", False)
            error = None if ok else result.get("output", "no response")
        await write_audit(
            session,
            action="instance.test",
            result="ok" if ok else "error",
            user_id=user.id,
            target_type="instance",
            target_id=inst.id,
            source_ip=client_ip(request),
            detail={"latency_ms": latency_ms, "error": error, "mode": "agent"},
        )
        await session.commit()
        return TestConnectionResponse(
            ok=ok, status_code=200 if ok else None, latency_ms=latency_ms, error=error
        )

    ok, status_code, latency_ms, error = await service.test_connection(inst)
    await write_audit(
        session,
        action="instance.test",
        result="ok" if ok else "error",
        user_id=user.id,
        target_type="instance",
        target_id=inst.id,
        source_ip=client_ip(request),
        detail={"latency_ms": latency_ms, "error": error},
    )
    await session.commit()
    return TestConnectionResponse(
        ok=ok, status_code=status_code, latency_ms=latency_ms, error=error
    )


class InstanceMoveGroup(BaseModel):
    group_id: int


@router.put("/{instance_id}/group", response_model=InstanceResponse)
async def move_group(
    instance_id: int,
    payload: InstanceMoveGroup,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_admin_or_superadmin),
) -> Instance:
    """Move an instance to another group.

    Superadmin: any instance to any group. Role admin: member of BOTH source
    and target group. A dedicated endpoint (not part of the generic PATCH)
    because moving is a rights operation, not instance config.
    """
    # Superadmins bypass visibility scoping — they may move instances they
    # cannot otherwise see (rights management without instance access).
    inst = await service.get_instance(session, instance_id, None if user.is_superadmin else user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if user.is_superadmin:
        if await session.get(Group, payload.group_id) is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown group")
    elif payload.group_id not in user.group_id_set:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="not a member of the target group"
        )
    old_group_id = inst.group_id
    inst.group_id = payload.group_id
    await write_audit(
        session,
        action="instance.move_group",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=inst.id,
        source_ip=client_ip(request),
        detail={"from_group_id": old_group_id, "to_group_id": payload.group_id},
    )
    await session.commit()
    await session.refresh(inst)
    return inst
