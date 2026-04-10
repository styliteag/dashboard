"""REST endpoints for OPNsense instance management.

Closes US-2.1, US-2.2, US-2.3, US-2.4, US-2.5.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import current_user
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
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="instance name already exists"
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
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="instance name already exists"
        ) from exc
    await write_audit(
        session,
        action="instance.update",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=inst.id,
        source_ip=_client_ip(request),
        detail=payload.model_dump(exclude_none=True, exclude={"api_key", "api_secret"}),
    )
    await session.commit()
    await session.refresh(inst)
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
