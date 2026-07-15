"""Bulk actions + CSV export across multiple instances."""

from __future__ import annotations

import asyncio
import csv
import io
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.auth.scope import scope_clause
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances.service import list_instances
from app.net import client_ip
from app.xsense.client import OPNsenseError
from app.xsense.registry import registry

router = APIRouter(tags=["bulk"])


# --- Bulk Actions -----------------------------------------------------------

# Agent-mode instances take commands over the hub, not the HTTP API.
# Maps bulk action name → (agent command, wait timeout). firmware.check runs a
# full repo sync on the box (90s, same as the single-instance route); the others
# just spawn a background process and return immediately.
_AGENT_COMMANDS: dict[str, tuple[str, float]] = {
    "firmware_check": ("firmware.check", 90),
    "firmware_update": ("firmware.update", 30),
    # Series/major upgrade (agent >= 3.1.1): the agent refuses when the vendor
    # offers no target and creates a boot environment first — 60s covers that.
    "firmware_upgrade": ("firmware.upgrade", 60),
    "ipsec_restart": ("ipsec.restart", 30),
    "reboot": ("reboot", 30),
}


class BulkActionRequest(BaseModel):
    instance_ids: list[int]
    # "firmware_check" | "firmware_update" | "firmware_upgrade" | "ipsec_restart" | "reboot"
    action: str


class BulkResult(BaseModel):
    instance_id: int
    instance_name: str
    success: bool
    message: str


class BulkActionResponse(BaseModel):
    results: list[BulkResult]
    total: int
    succeeded: int
    failed: int


@router.post("/bulk/action", response_model=BulkActionResponse)
async def bulk_action(
    payload: BulkActionRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> BulkActionResponse:
    """Run an action on multiple instances in parallel.

    Caller-supplied ids outside the user's groups are silently dropped by the
    scope filter — never acted on, never confirmed to exist.
    """
    stmt = select(Instance).where(
        Instance.id.in_(payload.instance_ids),
        Instance.deleted_at.is_(None),
    )
    clause = scope_clause(user)
    if clause is not None:
        stmt = stmt.where(clause)
    instances = (await session.execute(stmt)).scalars().all()

    async def run_agent(inst: Instance) -> BulkResult:
        agent = hub.get(inst.id)
        if agent is None:
            return BulkResult(
                instance_id=inst.id,
                instance_name=inst.name,
                success=False,
                message="agent not connected",
            )
        command, timeout = _AGENT_COMMANDS[payload.action]
        raw = await agent.send_command(command, timeout=timeout)
        return BulkResult(
            instance_id=inst.id,
            instance_name=inst.name,
            success=raw.get("success", False),
            message=raw.get("output", "")[:200],
        )

    async def run_one(inst: Instance) -> BulkResult:
        if payload.action not in _AGENT_COMMANDS:
            return BulkResult(
                instance_id=inst.id,
                instance_name=inst.name,
                success=False,
                message=f"unknown action: {payload.action}",
            )
        if payload.action in ("firmware_update", "firmware_upgrade") and inst.firmware_locked:
            return BulkResult(
                instance_id=inst.id,
                instance_name=inst.name,
                success=False,
                message="firmware updates are locked for this instance",
            )
        if payload.action == "firmware_upgrade" and not inst.agent_mode:
            # Mirrors the single-instance route (501): the series upgrade needs
            # the agent to resolve the target on-box and snapshot first.
            return BulkResult(
                instance_id=inst.id,
                instance_name=inst.name,
                success=False,
                message="series upgrade requires agent mode; use the vendor gui",
            )
        try:
            if inst.agent_mode:
                return await run_agent(inst)
            client = await registry.get(inst)
            if payload.action == "firmware_check":
                result = await client.firmware_check()
            elif payload.action == "firmware_update":
                result = await client.firmware_update()
            elif payload.action == "ipsec_restart":
                result = await client.ipsec_restart()
            else:  # "reboot"
                result = await client.reboot()
            return BulkResult(
                instance_id=inst.id,
                instance_name=inst.name,
                success=result.success,
                message=result.message,
            )
        except (OPNsenseError, Exception) as exc:
            return BulkResult(
                instance_id=inst.id,
                instance_name=inst.name,
                success=False,
                message=str(exc),
            )

    results = await asyncio.gather(*(run_one(i) for i in instances))
    results = list(results)

    # Audit each action
    for r in results:
        await write_audit(
            session,
            action=f"bulk.{payload.action}",
            result="ok" if r.success else "error",
            user_id=user.id,
            target_type="instance",
            target_id=str(r.instance_id),
            source_ip=client_ip(request),
            detail={"message": r.message},
        )
    await session.commit()

    succeeded = sum(1 for r in results if r.success)
    return BulkActionResponse(
        results=results,
        total=len(results),
        succeeded=succeeded,
        failed=len(results) - succeeded,
    )


# --- Export -----------------------------------------------------------------


@router.get("/export/instances.csv")
async def export_instances_csv(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> StreamingResponse:
    """Export the caller's visible instances as CSV."""
    instances = await list_instances(session, user)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "Name",
            "URL",
            "Location",
            "Tags",
            "Status",
            "Last Success",
            "Last Error",
            "Error Message",
        ]
    )
    for inst in instances:
        status = (
            "online"
            if inst.last_success_at
            and (not inst.last_error_at or inst.last_success_at > inst.last_error_at)
            else "offline"
            if inst.last_error_at
            else "unknown"
        )
        writer.writerow(
            [
                inst.name,
                inst.base_url,
                inst.location or "",
                ", ".join(inst.tags) if inst.tags else "",
                status,
                inst.last_success_at.isoformat() if inst.last_success_at else "",
                inst.last_error_at.isoformat() if inst.last_error_at else "",
                inst.last_error_message or "",
            ]
        )

    buf.seek(0)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M")
    return StreamingResponse(
        content=buf,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="instances_{ts}.csv"'},
    )
