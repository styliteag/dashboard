"""Audit log helper.

Every state-changing action — auth events, instance CRUD, IPsec actions,
firmware updates — must call ``write_audit`` so we have a tamper-evident trail
(US-6.1). Read-only operations are not audited.
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog


async def write_audit(
    session: AsyncSession,
    *,
    action: str,
    result: str,
    user_id: int | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    request_id: str | None = None,
    detail: dict[str, Any] | None = None,
    source_ip: str | None = None,
) -> AuditLog:
    """Insert an audit-log row. Caller is responsible for committing the session."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        request_id=request_id or uuid.uuid4().hex,
        result=result,
        detail=detail,
        source_ip=source_ip,
    )
    session.add(entry)
    await session.flush()
    return entry
