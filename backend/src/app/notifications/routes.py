"""Admin REST for notifications: per-channel alert-category routing + a test send."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_admin
from app.db.base import get_session
from app.db.models import Instance, User
from app.net import client_ip
from app.notifications.notifier import channel_configured, send_test_notification
from app.notifications.routing import CATEGORIES, CHANNELS, valid_category, valid_channel
from app.notifications.store import current_routes, load_routes, remove_route, set_route

router = APIRouter(prefix="/notifications", tags=["notifications"])


class ChannelResultOut(BaseModel):
    channel: str
    status: str  # "sent" | "skipped" | "failed"
    detail: str


class ChannelInfo(BaseModel):
    key: str
    configured: bool


class InstanceInfo(BaseModel):
    id: int
    name: str
    device_type: str


class RouteOut(BaseModel):
    instance_id: int | None  # None = global (every instance)
    channel: str
    category: str
    enabled: bool  # False = a per-instance off-override (global rows are always True)


class RoutingMatrix(BaseModel):
    channels: list[ChannelInfo]
    categories: list[str]
    instances: list[InstanceInfo]
    routes: list[RouteOut]


class RouteInput(BaseModel):
    instance_id: int | None = None  # None = global route (every instance)
    channel: str = Field(min_length=1, max_length=32)
    category: str = Field(min_length=1, max_length=64)
    enabled: bool = True  # False = explicit per-instance off-override (not valid globally)


def _audit_target_id(instance_id: int | None, channel: str, category: str) -> str:
    """Stable audit id. Includes ``instance_id`` so a global and a per-instance route
    for the same (channel, category) are not audit-indistinguishable."""
    return f"{instance_id if instance_id is not None else 'global'}:{channel}:{category}"


@router.get("/routing", response_model=RoutingMatrix)
async def get_routing(
    session: AsyncSession = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> RoutingMatrix:
    """The channels (with whether each is configured), the selectable alert
    categories, the instances a route can be scoped to, and the currently-subscribed
    ``(instance_id, channel, category)`` routes (``instance_id`` NULL = global)."""
    routes = sorted(current_routes(), key=lambda r: (r[0] or 0, r[1], r[2]))
    # routes are (instance_id, channel, category, enabled)
    instances = (
        (
            await session.execute(
                select(Instance).where(Instance.deleted_at.is_(None)).order_by(Instance.name)
            )
        )
        .scalars()
        .all()
    )
    return RoutingMatrix(
        channels=[ChannelInfo(key=c, configured=channel_configured(c)) for c in CHANNELS],
        categories=list(CATEGORIES),
        instances=[
            InstanceInfo(id=i.id, name=i.name, device_type=i.device_type) for i in instances
        ],
        routes=[
            RouteOut(instance_id=iid, channel=c, category=cat, enabled=en)
            for iid, c, cat, en in routes
        ],
    )


def _validate(channel: str, category: str) -> None:
    if not valid_channel(channel):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown channel")
    if not valid_category(category):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown category")


async def _require_instance(session: AsyncSession, instance_id: int | None) -> None:
    """A per-instance route must target a live instance (NULL = global, always OK)."""
    if instance_id is None:
        return
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="instance not found")


@router.post("/routes", response_model=RouteOut)
async def subscribe(
    payload: RouteInput,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> RouteOut:
    """Upsert a route (idempotent). ``instance_id`` NULL = a global route; a value
    scopes it to that one instance. ``enabled=False`` is a per-instance off-override
    (suppress a globally-on category for one box); it is invalid at global scope —
    turning a category off for all means *removing* the global route, not disabling
    it (DELETE ``/routes``)."""
    _validate(payload.channel, payload.category)
    if payload.instance_id is None and not payload.enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="a global route can't be disabled; remove it instead",
        )
    await _require_instance(session, payload.instance_id)
    await set_route(
        session, payload.channel, payload.category, payload.instance_id, payload.enabled
    )
    await write_audit(
        session,
        action="notify.route.set",
        result="ok",
        user_id=admin.id,
        target_type="notification_route",
        target_id=_audit_target_id(payload.instance_id, payload.channel, payload.category),
        source_ip=client_ip(request),
        detail={
            "instance_id": payload.instance_id,
            "channel": payload.channel,
            "category": payload.category,
            "enabled": payload.enabled,
        },
    )
    await session.commit()
    await load_routes(session)  # resync cache from committed state
    return RouteOut(
        instance_id=payload.instance_id,
        channel=payload.channel,
        category=payload.category,
        enabled=payload.enabled,
    )


@router.delete("/routes")
async def unsubscribe(
    channel: str,
    category: str,
    request: Request,
    instance_id: int | None = None,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> dict:
    """Unsubscribe a channel from an alert category (query params). Omit
    ``instance_id`` to remove the global route; pass it to remove a per-instance one."""
    _validate(channel, category)
    existed = await remove_route(session, channel, category, instance_id)
    if existed:
        await write_audit(
            session,
            action="notify.route.remove",
            result="ok",
            user_id=admin.id,
            target_type="notification_route",
            target_id=_audit_target_id(instance_id, channel, category),
            source_ip=client_ip(request),
            detail={"instance_id": instance_id, "channel": channel, "category": category},
        )
    await session.commit()
    await load_routes(session)  # resync cache from committed state
    return {"ok": True, "removed": existed}


@router.post("/test", response_model=list[ChannelResultOut])
async def test_notifications(
    channel: str | None = None, _admin: User = Depends(require_admin)
) -> list[ChannelResultOut]:
    """Send a test notification (ignoring subscriptions); report per-channel status.
    With ``?channel=`` only that channel is tested."""
    results = await send_test_notification(channel)
    return [ChannelResultOut(channel=r.channel, status=r.status, detail=r.detail) for r in results]
