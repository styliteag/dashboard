"""Admin REST for the Checkmk export config: which checks are exposed + preview.

All endpoints are admin-only. Exclusions affect **only** the Checkmk export; the
dashboard's own check views stay complete.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_admin
from app.checkmk.exclusions import CATEGORIES, Rule, category, excluded_reason
from app.checks import evaluate_checks
from app.checks.overlay import overlay_checks
from app.checks.routes import gather_many
from app.db.base import get_session
from app.db.models import CheckmkExportExclusion, Instance, User
from app.net import client_ip
from app.settings.store import effective_settings

router = APIRouter(prefix="/checkmk", tags=["checkmk"])


class CategoryState(BaseModel):
    key: str
    excluded: bool


class ExclusionRule(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    instance_id: int | None
    target: str


class CheckmkConfig(BaseModel):
    categories: list[CategoryState]
    rules: list[ExclusionRule]


class ExclusionInput(BaseModel):
    instance_id: int | None = None
    target: str = Field(min_length=1, max_length=255)


class PreviewCheck(BaseModel):
    key: str
    category: str
    state: int
    summary: str
    excluded: bool
    excluded_by: str | None  # "category" | "specific" | None


class PreviewInstance(BaseModel):
    instance_id: int
    name: str
    device_type: str
    checks: list[PreviewCheck]


class CheckmkPreview(BaseModel):
    instances: list[PreviewInstance]


async def _load_rules(session: AsyncSession) -> list[Rule]:
    rows = (await session.execute(select(CheckmkExportExclusion))).scalars().all()
    return [(r.instance_id, r.target) for r in rows]


@router.get("/config", response_model=CheckmkConfig)
async def get_config(
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> CheckmkConfig:
    rows = (
        (await session.execute(select(CheckmkExportExclusion).order_by(CheckmkExportExclusion.id)))
        .scalars()
        .all()
    )
    global_cats = {r.target for r in rows if r.instance_id is None}
    categories = [CategoryState(key=c, excluded=c in global_cats) for c in CATEGORIES]
    rules = [ExclusionRule.model_validate(r) for r in rows]
    return CheckmkConfig(categories=categories, rules=rules)


@router.post("/exclusions", response_model=ExclusionRule)
async def add_exclusion(
    payload: ExclusionInput,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> ExclusionRule:
    if payload.instance_id is not None:
        inst = await session.get(Instance, payload.instance_id)
        if inst is None or inst.deleted_at is not None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="instance not found")

    stmt = select(CheckmkExportExclusion).where(CheckmkExportExclusion.target == payload.target)
    stmt = stmt.where(
        CheckmkExportExclusion.instance_id.is_(None)
        if payload.instance_id is None
        else CheckmkExportExclusion.instance_id == payload.instance_id
    )
    existing = (await session.execute(stmt)).scalar_one_or_none()
    if existing is not None:
        return ExclusionRule.model_validate(existing)  # idempotent

    rule = CheckmkExportExclusion(instance_id=payload.instance_id, target=payload.target)
    session.add(rule)
    await session.flush()
    await write_audit(
        session,
        action="checkmk.exclusion.add",
        result="ok",
        user_id=admin.id,
        target_type="checkmk_exclusion",
        target_id=str(rule.id),
        source_ip=client_ip(request),
        detail={"instance_id": payload.instance_id, "target": payload.target},
    )
    await session.commit()
    return ExclusionRule.model_validate(rule)


@router.delete("/exclusions/{rule_id}")
async def remove_exclusion(
    rule_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> dict:
    rule = await session.get(CheckmkExportExclusion, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    detail = {"instance_id": rule.instance_id, "target": rule.target}
    await session.delete(rule)
    await write_audit(
        session,
        action="checkmk.exclusion.remove",
        result="ok",
        user_id=admin.id,
        target_type="checkmk_exclusion",
        target_id=str(rule_id),
        source_ip=client_ip(request),
        detail=detail,
    )
    await session.commit()
    return {"ok": True}


@router.get("/preview", response_model=CheckmkPreview)
async def preview(
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> CheckmkPreview:
    """Live view of what the export currently emits, annotated with exclusions.

    Polls direct-mode instances live (same caveat as ``/export/checkmk``): slow
    with many of them.
    """
    rules = await _load_rules(session)
    rows = (
        (
            await session.execute(
                select(Instance).where(Instance.deleted_at.is_(None)).order_by(Instance.name)
            )
        )
        .scalars()
        .all()
    )
    settings = effective_settings()
    now = datetime.now(UTC)
    instances: list[PreviewInstance] = []
    for inst, (sys_status, gateways, ipsec, firmware, services, certs) in await gather_many(rows):
        checks = overlay_checks(
            inst,
            evaluate_checks(sys_status, gateways, ipsec, firmware, services, certs),
            settings,
            now,
        )
        pchecks: list[PreviewCheck] = []
        for c in checks:
            reason = excluded_reason(c.key, inst.id, rules)
            pchecks.append(
                PreviewCheck(
                    key=c.key,
                    category=category(c.key),
                    state=c.state,
                    summary=c.summary,
                    excluded=reason is not None,
                    excluded_by=reason,
                )
            )
        instances.append(
            PreviewInstance(
                instance_id=inst.id,
                name=inst.name,
                device_type=inst.device_type,
                checks=pchecks,
            )
        )
    return CheckmkPreview(instances=instances)
