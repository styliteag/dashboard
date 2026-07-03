"""Lifecycle: dashboard-triggered agent uninstall + one-time-code enrollment (§16)."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.agent_hub.routes.management import _as_utc
from app.audit.log import write_audit
from app.auth.deps import require_write
from app.auth.security import limiter
from app.db.base import get_session
from app.db.models import EnrollmentCode, Instance, User
from app.devices.types import Transport
from app.instances.service import get_instance
from app.net import client_ip

log = structlog.get_logger("app.agent_hub.routes")

router = APIRouter(tags=["agent"])

# --- Lifecycle: uninstall + enrollment (§16 chunk C) -------------------------


@router.post("/instances/{instance_id}/agent/uninstall")
async def uninstall_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Tell the connected agent to remove itself, then drop agent mode.

    The agent acks and a detached script tears it down (supervisor first); on a
    successful ack we revoke the token and fall back to direct transport so the
    dashboard stops expecting a push agent.
    """
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )

    result = await agent.send_command("agent.uninstall", {"deprovision": True}, timeout=30)
    if result.get("success"):
        inst.transport = Transport.DIRECT.value
        inst.agent_token = None
        hub.unregister(instance_id)

    await write_audit(
        session,
        action="agent.uninstall",
        result="ok" if result.get("success") else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"result": result},
    )
    await session.commit()
    return {"sent": True, "result": result}


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


class EnrollCodeResponse(BaseModel):
    code: str
    instance_id: int
    expires_at: str


class EnrollRequest(BaseModel):
    code: str


class EnrollResponse(BaseModel):
    agent_token: str
    instance_id: int


@router.post("/instances/{instance_id}/agent/enroll-code", response_model=EnrollCodeResponse)
async def create_enroll_code(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> EnrollCodeResponse:
    """Mint a one-time, 1-hour enrollment code for an instance (admin only).

    The agent trades it at /agent/enroll for this instance's token, so the token
    never has to be pasted by hand. Only the code's SHA-256 is stored.
    """
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    code = secrets.token_urlsafe(24)
    expires_at = datetime.now(UTC) + timedelta(hours=1)
    session.add(
        EnrollmentCode(
            code_hash=_hash_code(code),
            instance_id=instance_id,
            expires_at=expires_at,
        )
    )
    await write_audit(
        session,
        action="agent.enroll_code",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return EnrollCodeResponse(code=code, instance_id=instance_id, expires_at=expires_at.isoformat())


@router.post("/agent/enroll", response_model=EnrollResponse)
async def enroll_agent(
    payload: EnrollRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> EnrollResponse:
    """Public: exchange a valid one-time code for an instance's agent token.

    Unauthenticated attack surface → rate-limited per IP with the login limiter.
    The code must be unused and unexpired; it is consumed on success.
    """
    ip = client_ip(request)
    if limiter.is_locked(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many attempts; try again later",
        )

    row = (
        await session.execute(
            select(EnrollmentCode).where(EnrollmentCode.code_hash == _hash_code(payload.code))
        )
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    # MariaDB DATETIME reads back naive (still UTC) — tag it before comparing.
    expired = row is not None and _as_utc(row.expires_at) < now
    if row is None or row.used_at is not None or expired:
        limiter.record_failure(ip)
        await write_audit(
            session,
            action="agent.enroll",
            result="denied",
            source_ip=ip,
            detail={"reason": "invalid_or_expired"},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired code"
        )

    inst = await session.get(Instance, row.instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="instance not found")

    limiter.record_success(ip)
    if not inst.agent_token:
        inst.agent_token = secrets.token_urlsafe(48)
    inst.transport = Transport.PUSH.value
    row.used_at = now

    await write_audit(
        session,
        action="agent.enroll",
        result="ok",
        target_type="instance",
        target_id=str(inst.id),
        source_ip=ip,
    )
    await session.commit()
    return EnrollResponse(agent_token=inst.agent_token, instance_id=inst.id)
