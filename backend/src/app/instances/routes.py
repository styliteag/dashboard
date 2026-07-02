"""REST endpoints for OPNsense instance management.

Closes US-2.1, US-2.2, US-2.3, US-2.4, US-2.5.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub import gui_caddy
from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.config import get_settings
from app.db.base import get_session
from app.db.models import Instance, User
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
    _user: User = Depends(current_user),
) -> list[InstanceResponse]:
    rows = await service.list_instances(session)
    settings = effective_settings()
    now = datetime.now(UTC)
    return [instance_response(inst, settings, now) for inst in rows]


@router.post("", response_model=InstanceResponse, status_code=status.HTTP_201_CREATED)
async def create(
    payload: InstanceCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> Instance:
    try:
        inst = await service.create_instance(session, payload)
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
    _user: User = Depends(current_user),
) -> InstanceResponse:
    inst = await service.get_instance(session, instance_id)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return instance_response(inst, effective_settings(), datetime.now(UTC))


@router.patch("/{instance_id}", response_model=InstanceResponse)
async def update(
    instance_id: int,
    payload: InstanceUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> Instance:
    inst = await service.get_instance(session, instance_id)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
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
    inst = await service.get_instance(session, instance_id)
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
    inst = await service.get_instance(session, instance_id)
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
