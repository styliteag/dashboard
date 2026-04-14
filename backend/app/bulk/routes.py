"""Bulk actions + CSV export across multiple instances."""
from __future__ import annotations

import asyncio
import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import current_user
from app.db.base import get_session
from app.db.models import Instance, User
from app.opnsense.client import OPNsenseError
from app.opnsense.registry import registry

router = APIRouter(tags=["bulk"])


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


# --- Bulk Actions -----------------------------------------------------------

class BulkActionRequest(BaseModel):
    instance_ids: list[int]
    action: str  # "firmware_check" | "ipsec_restart"


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
    user: User = Depends(current_user),
) -> BulkActionResponse:
    """Run an action on multiple instances in parallel."""
    instances = (
        await session.execute(
            select(Instance).where(
                Instance.id.in_(payload.instance_ids),
                Instance.deleted_at.is_(None),
            )
        )
    ).scalars().all()

    async def run_one(inst: Instance) -> BulkResult:
        try:
            client = await registry.get(inst)
            if payload.action == "firmware_check":
                result = await client.firmware_check()
            elif payload.action == "ipsec_restart":
                result = await client.ipsec_restart()
            elif payload.action == "reboot":
                result = await client.reboot()
            else:
                return BulkResult(
                    instance_id=inst.id, instance_name=inst.name,
                    success=False, message=f"unknown action: {payload.action}",
                )
            return BulkResult(
                instance_id=inst.id, instance_name=inst.name,
                success=result.success, message=result.message,
            )
        except (OPNsenseError, Exception) as exc:
            return BulkResult(
                instance_id=inst.id, instance_name=inst.name,
                success=False, message=str(exc),
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
            source_ip=_client_ip(request),
            detail={"message": r.message},
        )
    await session.commit()

    succeeded = sum(1 for r in results if r.success)
    return BulkActionResponse(
        results=results, total=len(results),
        succeeded=succeeded, failed=len(results) - succeeded,
    )


# --- Export -----------------------------------------------------------------

@router.get("/export/instances.csv")
async def export_instances_csv(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> StreamingResponse:
    """Export all instances as CSV."""
    instances = (
        await session.execute(
            select(Instance).where(Instance.deleted_at.is_(None)).order_by(Instance.name)
        )
    ).scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Name", "URL", "Location", "Tags", "Status",
        "Last Success", "Last Error", "Error Message",
    ])
    for inst in instances:
        status = "online" if inst.last_success_at and (
            not inst.last_error_at or inst.last_success_at > inst.last_error_at
        ) else "offline" if inst.last_error_at else "unknown"
        writer.writerow([
            inst.name,
            inst.base_url,
            inst.location or "",
            ", ".join(inst.tags) if inst.tags else "",
            status,
            inst.last_success_at.isoformat() if inst.last_success_at else "",
            inst.last_error_at.isoformat() if inst.last_error_at else "",
            inst.last_error_message or "",
        ])

    buf.seek(0)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    return StreamingResponse(
        content=buf,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="instances_{ts}.csv"'},
    )
