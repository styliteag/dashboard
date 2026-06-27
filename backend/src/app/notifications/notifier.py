"""Notification dispatcher — sends alerts to all configured channels.

Channels (each optional): generic webhook, Telegram, ntfy, Mattermost. The
Mattermost webhook URL is editable in the Settings UI (secret); the others come
from the environment (``DASH_NOTIFY_*``). Values are read through
``effective_settings()`` so a DB override applies live. Failures are logged,
never raised.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import structlog

from app.settings.store import effective_settings

log = structlog.get_logger("app.notifications")


@dataclass(frozen=True)
class ChannelResult:
    channel: str
    status: str  # "sent" | "skipped" | "failed"
    detail: str = ""


def _result(channel: str, resp: httpx.Response) -> ChannelResult:
    """Map an HTTP response to a result — a >=400 status is a failure, not 'sent'."""
    if resp.status_code >= 400:
        log.warning(f"notify.{channel}.failed", status=resp.status_code)
        return ChannelResult(channel, "failed", f"HTTP {resp.status_code}")
    log.info(f"notify.{channel}.sent", status=resp.status_code)
    return ChannelResult(channel, "sent")


async def _send_webhook(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    url = getattr(s, "notify_webhook_url", "") or ""
    if not url:
        return ChannelResult("webhook", "skipped")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(url, json={"title": title, "message": message, "level": level})
        return _result("webhook", resp)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.webhook.failed", error=str(exc))
        return ChannelResult("webhook", "failed", str(exc))


async def _send_telegram(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    token = getattr(s, "notify_telegram_token", "") or ""
    chat = getattr(s, "notify_telegram_chat_id", "") or ""
    if not (token and chat):
        return ChannelResult("telegram", "skipped")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat, "text": f"*{title}*\n{message}", "parse_mode": "Markdown"},
            )
        return _result("telegram", resp)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.telegram.failed", error=str(exc))
        return ChannelResult("telegram", "failed", str(exc))


async def _send_ntfy(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    url = getattr(s, "notify_ntfy_url", "") or ""
    if not url:
        return ChannelResult("ntfy", "skipped")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(
                url,
                content=message,
                headers={
                    "Title": title,
                    "Priority": {"error": "high", "warning": "default"}.get(level, "low"),
                    "Tags": "shield",
                },
            )
        return _result("ntfy", resp)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.ntfy.failed", error=str(exc))
        return ChannelResult("ntfy", "failed", str(exc))


async def _send_mattermost(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    url = getattr(s, "notify_mattermost_url", "") or ""
    if not url:
        return ChannelResult("mattermost", "skipped")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(url, json={"text": f"**{title}**\n{message}"})
        return _result("mattermost", resp)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.mattermost.failed", error=str(exc))
        return ChannelResult("mattermost", "failed", str(exc))


async def _dispatch(title: str, message: str, level: str) -> list[ChannelResult]:
    s = effective_settings()
    return [
        await _send_webhook(s, title, message, level),
        await _send_telegram(s, title, message, level),
        await _send_ntfy(s, title, message, level),
        await _send_mattermost(s, title, message, level),
    ]


async def send_notification(title: str, message: str, level: str = "info") -> None:
    """Send to all configured channels. Failures are logged, not raised."""
    await _dispatch(title, message, level)


async def send_test_notification() -> list[ChannelResult]:
    """Send a test message and report per-channel status (for the Settings UI)."""
    return await _dispatch(
        "Orbit test notification",
        "If you can read this, Orbit notifications are working.",
        "info",
    )
