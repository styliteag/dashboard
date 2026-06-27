"""Notification dispatcher — sends alerts to all configured channels.

Channels (each optional): generic webhook, Telegram, ntfy, Mattermost. The
Mattermost webhook URL is editable in the Settings UI (secret); the others come
from the environment (``DASH_NOTIFY_*``). Values are read through
``effective_settings()`` so a DB override applies live. Failures are logged,
never raised.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

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


def _split_ntfy_url(url: str) -> tuple[str, str]:
    """Split an ntfy topic URL into ``(server_base, topic)``.

    ntfy's JSON publishing API must be POSTed to the server *root* with the topic in
    the body — POSTing JSON to the topic URL would publish the literal JSON as the
    message text (and still return 200). Returns ``("", "")`` when there is no topic
    segment, so the caller can fail instead of dumping JSON to the root.
    """
    parsed = urlparse(url)
    segments = [seg for seg in parsed.path.split("/") if seg]
    if not parsed.scheme or not parsed.netloc or not segments:
        return "", ""
    topic = segments[-1]
    base = f"{parsed.scheme}://{parsed.netloc}"
    base_path = "/".join(segments[:-1])
    if base_path:
        base = f"{base}/{base_path}"
    return base, topic


# ntfy JSON priority is numeric 1-5; matches the old high/default/low header values.
_NTFY_PRIORITY = {"error": 4, "warning": 3}


async def _send_ntfy(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    url = getattr(s, "notify_ntfy_url", "") or ""
    if not url:
        return ChannelResult("ntfy", "skipped")
    base, topic = _split_ntfy_url(url)
    if not topic:
        log.warning("notify.ntfy.failed", error="no topic in URL")
        return ChannelResult("ntfy", "failed", "ntfy URL has no topic")
    # JSON publishing carries the title in the UTF-8 body. The previous header form
    # ("Title") is latin-1 only, so every emoji-prefixed alert title (🔴/✅) raised
    # UnicodeEncodeError and the channel silently failed on every real alert.
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(
                base,
                json={
                    "topic": topic,
                    "title": title,
                    "message": message,
                    "priority": _NTFY_PRIORITY.get(level, 2),
                    "tags": ["shield"],
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
    # Emoji-prefixed like real alert titles, so the Test button exercises the same
    # Unicode-encoding path a production alert takes (it previously did not).
    return await _dispatch(
        "✅ Orbit test notification",
        "If you can read this, Orbit notifications are working.",
        "info",
    )
