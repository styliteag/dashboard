"""Admin REST for service selection — one router for every consumer.

A *consumer* is the Checkmk export (``checkmk``) or a notification channel
(``mattermost`` / ``telegram`` / ``email``). All four share this config / rules /
preview UI; the channels also expose a test send. Selection affects only what each
consumer is interested in — the dashboard's own green/red views always show
everything. All endpoints are admin-only.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_admin
from app.checks import ServiceCheck, evaluate_checks
from app.checks.overlay import overlay_checks
from app.checks.routes import gather_many
from app.db.base import get_session
from app.db.models import Instance, SelectionRule, User
from app.instances.service import get_instance
from app.net import client_ip
from app.notifications.notifier import channel_configured, send_test_notification
from app.selection.model import (
    AVAILABILITY,
    CHANNELS,
    CHECKMK,
    INCLUDE,
    categories_for,
    category,
    resolve,
    valid_consumer,
    valid_mode,
    valid_selector,
)
from app.selection.store import fetch_rules, load_rules, remove_rule, set_rule
from app.settings.store import effective_settings

router = APIRouter(prefix="/selection", tags=["selection"])


class CategoryState(BaseModel):
    key: str
    included: bool  # a global include rule exists for this category


class RuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    instance_id: int | None
    selector: str
    mode: str  # "include" | "exclude"


class SelectionConfig(BaseModel):
    consumer: str
    configured: bool | None  # channel send-config status; None for checkmk
    categories: list[CategoryState]
    rules: list[RuleOut]


class RuleInput(BaseModel):
    instance_id: int | None = None
    selector: str = Field(min_length=1, max_length=255)
    mode: str = Field(min_length=1, max_length=8)


class PreviewCheck(BaseModel):
    key: str
    category: str
    state: int
    summary: str
    on: bool  # whether the consumer is interested in this check for this instance
    by: str  # "instance" | "instance_category" | "global" | "global_category" | "default"


class PreviewInstance(BaseModel):
    instance_id: int
    name: str
    device_type: str
    checks: list[PreviewCheck]


class SelectionPreview(BaseModel):
    instances: list[PreviewInstance]


class ChannelResultOut(BaseModel):
    channel: str
    status: str  # "sent" | "skipped" | "failed"
    detail: str


def _require_consumer(consumer: str) -> str:
    if not valid_consumer(consumer):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown consumer")
    return consumer


def _audit_target_id(consumer: str, instance_id: int | None, selector: str) -> str:
    return f"{consumer}:{instance_id if instance_id is not None else 'global'}:{selector}"


async def _require_instance(session: AsyncSession, instance_id: int | None, user: User) -> None:
    """A per-instance rule must target a live instance the admin can see
    (NULL = global, always OK)."""
    if instance_id is None:
        return
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="instance not found")


@router.get("/{consumer}/config", response_model=SelectionConfig)
async def get_config(
    consumer: str,
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> SelectionConfig:
    """The selectable categories (with whether each is globally included) plus every
    rule. The frontend re-implements ``resolve`` against ``rules`` so toggling only
    refetches this cheap config, not the live preview."""
    _require_consumer(consumer)
    rows = (
        (
            await session.execute(
                select(SelectionRule)
                .where(SelectionRule.consumer == consumer)
                .order_by(SelectionRule.id)
            )
        )
        .scalars()
        .all()
    )
    global_included = {r.selector for r in rows if r.instance_id is None and r.mode == INCLUDE}
    categories = [
        CategoryState(key=c, included=c in global_included) for c in categories_for(consumer)
    ]
    configured = None if consumer == CHECKMK else channel_configured(consumer)
    return SelectionConfig(
        consumer=consumer,
        configured=configured,
        categories=categories,
        rules=[RuleOut.model_validate(r) for r in rows],
    )


@router.post("/{consumer}/rules", response_model=RuleOut)
async def add_rule(
    consumer: str,
    payload: RuleInput,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> RuleOut:
    """Upsert an include/exclude rule (idempotent)."""
    _require_consumer(consumer)
    if not valid_mode(payload.mode):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown mode")
    if not valid_selector(consumer, payload.selector):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown selector")
    await _require_instance(session, payload.instance_id, admin)
    row = await set_rule(session, consumer, payload.selector, payload.mode, payload.instance_id)
    await write_audit(
        session,
        action="selection.rule.set",
        result="ok",
        user_id=admin.id,
        target_type="selection_rule",
        target_id=_audit_target_id(consumer, payload.instance_id, payload.selector),
        source_ip=client_ip(request),
        detail={
            "consumer": consumer,
            "instance_id": payload.instance_id,
            "selector": payload.selector,
            "mode": payload.mode,
        },
    )
    await session.commit()
    await load_rules(session)  # resync cache from committed state
    return RuleOut.model_validate(row)


@router.delete("/{consumer}/rules")
async def delete_rule(
    consumer: str,
    selector: str,
    request: Request,
    instance_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> dict:
    """Remove a rule (query params) — the check falls back to inherit / base default."""
    _require_consumer(consumer)
    existed = await remove_rule(session, consumer, selector, instance_id)
    if existed:
        await write_audit(
            session,
            action="selection.rule.remove",
            result="ok",
            user_id=admin.id,
            target_type="selection_rule",
            target_id=_audit_target_id(consumer, instance_id, selector),
            source_ip=client_ip(request),
            detail={"consumer": consumer, "instance_id": instance_id, "selector": selector},
        )
    await session.commit()
    await load_rules(session)  # resync cache from committed state
    return {"ok": True, "removed": existed}


def _availability_check() -> ServiceCheck:
    """A synthetic preview row for the channel-only ``availability`` signal (instance
    up/down). It isn't produced by ``evaluate_checks`` — it's its own bucket — but it
    is selectable per channel, so it must appear in the tree."""
    return ServiceCheck(key=AVAILABILITY, state=0, summary="Instance up / down alerts")


@router.get("/{consumer}/preview", response_model=SelectionPreview)
async def preview(
    consumer: str,
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> SelectionPreview:
    """Live view of every instance's checks annotated with this consumer's resolved
    on/off. Reads rules fresh from the DB (correct under multiple workers). Polls
    direct-mode instances live (same caveat as the export): slow with many."""
    _require_consumer(consumer)
    rules = await fetch_rules(session)
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
    is_channel = consumer in CHANNELS
    instances: list[PreviewInstance] = []
    for inst, (
        sys_status,
        gateways,
        ipsec,
        firmware,
        services,
        certs,
        connectivity,
    ) in await gather_many(rows):
        evaluated = overlay_checks(
            inst,
            evaluate_checks(sys_status, gateways, ipsec, firmware, services, certs, connectivity),
            settings,
            now,
        )
        checks = [_availability_check(), *evaluated] if is_channel else list(evaluated)
        pchecks: list[PreviewCheck] = []
        for c in checks:
            on, by = resolve(consumer, c.key, inst.id, rules)
            pchecks.append(
                PreviewCheck(
                    key=c.key,
                    category=category(c.key),
                    state=c.state,
                    summary=c.summary,
                    on=on,
                    by=by,
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
    return SelectionPreview(instances=instances)


@router.post("/{consumer}/test", response_model=list[ChannelResultOut])
async def test_channel(
    consumer: str, _admin: User = Depends(require_admin)
) -> list[ChannelResultOut]:
    """Send a test notification on a channel (ignoring selection). Channels only."""
    _require_consumer(consumer)
    if consumer not in CHANNELS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="test is for channels only"
        )
    results = await send_test_notification(consumer)
    return [ChannelResultOut(channel=r.channel, status=r.status, detail=r.detail) for r in results]
