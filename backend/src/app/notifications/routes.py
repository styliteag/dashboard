"""Admin REST for notifications: send a test message and report per-channel status."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.auth.deps import require_admin
from app.db.models import User
from app.notifications.notifier import send_test_notification

router = APIRouter(prefix="/notifications", tags=["notifications"])


class ChannelResultOut(BaseModel):
    channel: str
    status: str  # "sent" | "skipped" | "failed"
    detail: str


@router.post("/test", response_model=list[ChannelResultOut])
async def test_notifications(_admin: User = Depends(require_admin)) -> list[ChannelResultOut]:
    """Send a test notification to every configured channel; report what happened."""
    results = await send_test_notification()
    return [ChannelResultOut(channel=r.channel, status=r.status, detail=r.detail) for r in results]
