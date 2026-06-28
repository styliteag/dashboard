"""Admin REST for notifications: per-channel alert-category routing + a test send."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.log import write_audit
from app.auth.deps import require_admin
from app.db.base import get_session
from app.db.models import User
from app.net import client_ip
from app.notifications.notifier import channel_configured, send_test_notification
from app.notifications.routing import CATEGORIES, CHANNELS, valid_category, valid_channel
from app.notifications.store import add_route, current_routes, load_routes, remove_route

router = APIRouter(prefix="/notifications", tags=["notifications"])


class ChannelResultOut(BaseModel):
    channel: str
    status: str  # "sent" | "skipped" | "failed"
    detail: str


class ChannelInfo(BaseModel):
    key: str
    configured: bool


class RouteOut(BaseModel):
    channel: str
    category: str


class RoutingMatrix(BaseModel):
    channels: list[ChannelInfo]
    categories: list[str]
    routes: list[RouteOut]


class RouteInput(BaseModel):
    channel: str = Field(min_length=1, max_length=32)
    category: str = Field(min_length=1, max_length=64)


@router.get("/routing", response_model=RoutingMatrix)
async def get_routing(_admin: User = Depends(require_admin)) -> RoutingMatrix:
    """The channels (with whether each is configured), the selectable alert
    categories, and the currently-subscribed (channel, category) pairs."""
    routes = sorted(current_routes())
    return RoutingMatrix(
        channels=[ChannelInfo(key=c, configured=channel_configured(c)) for c in CHANNELS],
        categories=list(CATEGORIES),
        routes=[RouteOut(channel=c, category=cat) for c, cat in routes],
    )


def _validate(payload: RouteInput) -> None:
    if not valid_channel(payload.channel):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown channel")
    if not valid_category(payload.category):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown category")


@router.post("/routes", response_model=RouteOut)
async def subscribe(
    payload: RouteInput,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> RouteOut:
    """Subscribe a channel to an alert category (idempotent)."""
    _validate(payload)
    await add_route(session, payload.channel, payload.category)
    await write_audit(
        session,
        action="notify.route.add",
        result="ok",
        user_id=admin.id,
        target_type="notification_route",
        target_id=f"{payload.channel}:{payload.category}",
        source_ip=client_ip(request),
        detail={"channel": payload.channel, "category": payload.category},
    )
    await session.commit()
    await load_routes(session)  # resync cache from committed state
    return RouteOut(channel=payload.channel, category=payload.category)


@router.delete("/routes")
async def unsubscribe(
    channel: str,
    category: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: User = Depends(require_admin),
) -> dict:
    """Unsubscribe a channel from an alert category (channel/category as query params)."""
    _validate(RouteInput(channel=channel, category=category))
    existed = await remove_route(session, channel, category)
    if existed:
        await write_audit(
            session,
            action="notify.route.remove",
            result="ok",
            user_id=admin.id,
            target_type="notification_route",
            target_id=f"{channel}:{category}",
            source_ip=client_ip(request),
            detail={"channel": channel, "category": category},
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
