"""Notification dispatcher — sends alerts via webhook, Telegram, or ntfy.

Configured via environment variables:
  DASH_NOTIFY_WEBHOOK_URL   — POST JSON to this URL
  DASH_NOTIFY_TELEGRAM_TOKEN + DASH_NOTIFY_TELEGRAM_CHAT_ID — Telegram bot
  DASH_NOTIFY_NTFY_URL      — ntfy topic URL (e.g. https://ntfy.sh/my-opnsense)
"""
from __future__ import annotations

import structlog
import httpx

from app.config import get_settings

log = structlog.get_logger("app.notifications")


async def send_notification(title: str, message: str, level: str = "info") -> None:
    """Send a notification to all configured channels. Failures are logged, not raised."""
    settings = get_settings()

    # Webhook
    webhook_url = getattr(settings, "notify_webhook_url", "") or ""
    if webhook_url:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                await c.post(webhook_url, json={
                    "title": title, "message": message, "level": level,
                })
            log.info("notify.webhook.sent", title=title)
        except Exception as exc:  # noqa: BLE001
            log.warning("notify.webhook.failed", error=str(exc))

    # Telegram
    tg_token = getattr(settings, "notify_telegram_token", "") or ""
    tg_chat = getattr(settings, "notify_telegram_chat_id", "") or ""
    if tg_token and tg_chat:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                await c.post(
                    f"https://api.telegram.org/bot{tg_token}/sendMessage",
                    json={"chat_id": tg_chat, "text": f"*{title}*\n{message}", "parse_mode": "Markdown"},
                )
            log.info("notify.telegram.sent", title=title)
        except Exception as exc:  # noqa: BLE001
            log.warning("notify.telegram.failed", error=str(exc))

    # ntfy
    ntfy_url = getattr(settings, "notify_ntfy_url", "") or ""
    if ntfy_url:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                await c.post(ntfy_url, content=message, headers={
                    "Title": title,
                    "Priority": {"error": "high", "warning": "default"}.get(level, "low"),
                    "Tags": "shield",
                })
            log.info("notify.ntfy.sent", title=title)
        except Exception as exc:  # noqa: BLE001
            log.warning("notify.ntfy.failed", error=str(exc))
