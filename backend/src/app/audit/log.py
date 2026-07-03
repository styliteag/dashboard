"""Audit log helper.

Every state-changing action — auth events, instance CRUD, IPsec actions,
firmware updates — must call ``write_audit`` so we have a tamper-evident trail
(US-6.1). Read-only operations are not audited.

Each row is mirrored as an ``app.audit`` log event (always visible in docker
logs, independent of the global level — see ``app.logsetup``). The line is
emitted before the caller commits: a rolled-back transaction still logged.
That's intentional — the log is an observability stream, the DB row is the
tamper-evident record.
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog

audit_log = structlog.get_logger("app.audit")

# detail is caller-defined and may carry payloads that don't belong in a log
# line (settings values, nested command results) — mirror only these keys.
_DETAIL_KEYS = ("reason", "username", "stage", "lock_triggered", "name", "role", "mode")


def _log_entry(
    action: str,
    result: str,
    user_id: int | None,
    target_type: str | None,
    target_id: str | int | None,
    source_ip: str | None,
    detail: dict[str, Any] | None,
) -> None:
    fields: dict[str, Any] = {"result": result}
    if user_id is not None:
        fields["user_id"] = user_id
    if target_type is not None:
        fields["target"] = f"{target_type}:{target_id}" if target_id is not None else target_type
    if source_ip is not None:
        fields["ip"] = source_ip
    if detail:
        fields.update({k: detail[k] for k in _DETAIL_KEYS if k in detail})
    level = "info" if result in ("ok", "pending") else "warning"
    getattr(audit_log, level)(action, **fields)
    if detail and detail.get("lock_triggered"):
        # The brute-force limiter just locked this IP — make it unmissable.
        audit_log.warning(
            "auth.ip_blocked", ip=source_ip, username=detail.get("username"), user_id=user_id
        )


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
    _log_entry(action, result, user_id, target_type, target_id, source_ip, detail)
    return entry
