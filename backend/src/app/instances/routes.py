"""REST endpoints for OPNsense instance management.

Closes US-2.1, US-2.2, US-2.3, US-2.4, US-2.5.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub import gui_caddy
from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user
from app.config import get_settings
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances import service
from app.instances.schemas import (
    InstanceCreate,
    InstanceResponse,
    InstanceUpdate,
    TestConnectionResponse,
)

router = APIRouter(prefix="/instances", tags=["instances"])


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


@router.get("", response_model=list[InstanceResponse])
async def list_all(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[Instance]:
    return await service.list_instances(session)


@router.post("", response_model=InstanceResponse, status_code=status.HTTP_201_CREATED)
async def create(
    payload: InstanceCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
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
        source_ip=_client_ip(request),
        detail={"name": inst.name},
    )
    await session.commit()
    await session.refresh(inst)
    await gui_caddy.reconcile(session)  # add this instance's vhost to the GUI proxy
    return inst


@router.get("/{instance_id}", response_model=InstanceResponse)
async def get(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> Instance:
    inst = await service.get_instance(session, instance_id)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return inst


@router.patch("/{instance_id}", response_model=InstanceResponse)
async def update(
    instance_id: int,
    payload: InstanceUpdate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
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
        source_ip=_client_ip(request),
        detail=payload.model_dump(
            mode="json", exclude_none=True, exclude={"api_key", "api_secret"}
        ),
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
    user: User = Depends(current_user),
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
        source_ip=_client_ip(request),
        detail={"name": inst.name},
    )
    await session.commit()
    await gui_caddy.reconcile(session)  # drop this instance's vhost from the GUI proxy


@router.post("/{instance_id}/test", response_model=TestConnectionResponse)
async def test(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
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
            source_ip=_client_ip(request),
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
        source_ip=_client_ip(request),
        detail={"latency_ms": latency_ms, "error": error},
    )
    await session.commit()
    return TestConnectionResponse(
        ok=ok, status_code=status_code, latency_ms=latency_ms, error=error
    )
