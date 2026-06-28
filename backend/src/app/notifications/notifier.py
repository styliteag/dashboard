"""Notification dispatcher — sends alerts to the subscribed channels.

Channels (each optional): Mattermost, Telegram, Email. All three are configurable
in the Settings UI; config values are read through ``effective_settings()`` so a DB
override applies live. Each alert carries a *category* (``availability`` or a check
category); a channel only receives it when it is subscribed to that category
(``app.notifications.store``). Failures are logged, never raised.
"""

from __future__ import annotations

import asyncio
import ipaddress
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from urllib.parse import urlparse

import httpx
import structlog

from app.notifications.routing import AVAILABILITY
from app.notifications.store import is_subscribed_live
from app.settings.store import effective_settings

log = structlog.get_logger("app.notifications")


async def _ssrf_block_reason(url: str) -> str | None:
    """Reject a user-configured webhook URL that would let the backend reach a
    dangerous-but-never-legitimate target. Returns a reason string, or None if OK.

    Blocks loopback, link-local (incl. the 169.254.169.254 cloud-metadata IP),
    reserved, multicast and unspecified addresses. RFC1918 **private** ranges are
    intentionally allowed: self-hosted Mattermost/ntfy/webhooks on an internal
    network are a legitimate (and common) target, and an admin can already reach
    those via instance config — so blocking them adds no protection.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "URL must be http(s) with a host"
    host = parsed.hostname
    try:
        addrs = [host] if _is_ip_literal(host) else await _resolve(host)
    except OSError:
        return "host does not resolve"
    for addr in addrs:
        ip = ipaddress.ip_address(addr)
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return f"blocked address {addr}"
    return None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _resolve(host: str) -> list[str]:
    infos = await asyncio.get_event_loop().getaddrinfo(host, None)
    return [info[4][0] for info in infos]


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


async def _send_telegram(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    token = getattr(s, "notify_telegram_token", "") or ""
    chat = getattr(s, "notify_telegram_chat_id", "") or ""
    if not (token and chat):
        return ChannelResult("telegram", "skipped")
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            # Plain text, no parse_mode: with Markdown an unbalanced metacharacter in
            # the title/message (e.g. a lone `*`/backtick from an error string, or a
            # truncation cutting through an entity) made Telegram reject the whole
            # message with HTTP 400 — silently dropping the alert that matters most
            # (the offline alert embeds an arbitrary error string). Reliability of
            # delivery beats a bold title.
            resp = await c.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat, "text": f"{title}\n{message}"},
            )
        return _result("telegram", resp)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.telegram.failed", error=str(exc))
        return ChannelResult("telegram", "failed", str(exc))


async def _send_mattermost(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    url = getattr(s, "notify_mattermost_url", "") or ""
    if not url:
        return ChannelResult("mattermost", "skipped")
    reason = await _ssrf_block_reason(url)
    if reason:
        log.warning("notify.mattermost.blocked", reason=reason)
        return ChannelResult("mattermost", "failed", reason)
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            resp = await c.post(url, json={"text": f"**{title}**\n{message}"})
        return _result("mattermost", resp)
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.mattermost.failed", error=str(exc))
        return ChannelResult("mattermost", "failed", str(exc))


def _parse_recipients(raw: str) -> list[str]:
    """Split a comma/whitespace-separated recipient string into addresses."""
    return [a for a in raw.replace(",", " ").split() if a]


def _smtp_send(
    *,
    host: str,
    port: int,
    security: str,
    sender: str,
    recipients: list[str],
    username: str,
    password: str,
    subject: str,
    body: str,
) -> None:
    """Blocking SMTP send — run via ``asyncio.to_thread``. Raises on any failure.

    ``security``: "ssl" = implicit TLS (465), "starttls" = upgrade after connect
    (587), "none" = plaintext (25). Authenticates only when a username is given.
    Kept sync + dependency-free (stdlib ``smtplib``) and separate from the async
    wrapper so it is trivial to monkeypatch in tests.
    """
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    if security == "ssl":
        with smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context()) as smtp:
            if username:
                smtp.login(username, password)
            smtp.send_message(msg)
        return
    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if security == "starttls":
            smtp.starttls(context=ssl.create_default_context())
        if username:
            smtp.login(username, password)
        smtp.send_message(msg)


async def _send_email(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    host = getattr(s, "notify_email_smtp_host", "") or ""
    sender = getattr(s, "notify_email_from", "") or ""
    recipients = _parse_recipients(getattr(s, "notify_email_to", "") or "")
    if not (host and sender and recipients):
        return ChannelResult("email", "skipped")
    try:
        await asyncio.to_thread(
            _smtp_send,
            host=host,
            port=int(getattr(s, "notify_email_smtp_port", 587) or 587),
            security=getattr(s, "notify_email_security", "starttls") or "starttls",
            sender=sender,
            recipients=recipients,
            username=getattr(s, "notify_email_username", "") or "",
            password=getattr(s, "notify_email_password", "") or "",
            subject=title,
            body=message,
        )
        log.info("notify.email.sent", recipients=len(recipients))
        return ChannelResult("email", "sent")
    except Exception as exc:  # noqa: BLE001
        log.warning("notify.email.failed", error=str(exc))
        return ChannelResult("email", "failed", str(exc))


def channel_configured(channel: str, s=None) -> bool:  # noqa: ANN001
    """Whether a channel has enough config to actually send (same predicate the
    senders use to decide skip-vs-send). Drives the 'subscribed but not configured'
    hint in the Settings UI."""
    s = s or effective_settings()
    if channel == "mattermost":
        return bool(getattr(s, "notify_mattermost_url", ""))
    if channel == "telegram":
        return bool(
            getattr(s, "notify_telegram_token", "") and getattr(s, "notify_telegram_chat_id", "")
        )
    if channel == "email":
        return bool(
            getattr(s, "notify_email_smtp_host", "")
            and getattr(s, "notify_email_from", "")
            and _parse_recipients(getattr(s, "notify_email_to", "") or "")
        )
    return False


# channel name -> sender. The dispatch order is the channel display order.
_CHANNEL_SENDERS = (
    ("mattermost", _send_mattermost),
    ("telegram", _send_telegram),
    ("email", _send_email),
)


async def _dispatch(
    title: str,
    message: str,
    level: str,
    category: str,
    instance_id: int | None,
    *,
    respect_routes: bool,
) -> list[ChannelResult]:
    """Send to each channel. When ``respect_routes`` is on, a channel not subscribed
    to ``category`` for ``instance_id`` is reported as skipped without attempting a
    send (the test path turns it off — and passes ``instance_id=None`` — to reach
    every configured channel)."""
    s = effective_settings()
    results: list[ChannelResult] = []
    for channel, sender in _CHANNEL_SENDERS:
        if respect_routes and not is_subscribed_live(channel, category, instance_id):
            results.append(ChannelResult(channel, "skipped", "not subscribed"))
            continue
        results.append(await sender(s, title, message, level))
    return results


async def send_notification(
    title: str, message: str, instance_id: int, level: str = "info", category: str = AVAILABILITY
) -> None:
    """Send an alert of ``category`` for ``instance_id`` to every subscribed channel.

    ``instance_id`` is required (not defaulted): routing resolves per instance (a
    per-instance route overrides the global one), so a missing id would silently
    match only global routes and ignore every per-instance override — a forgotten
    call site must fail loudly, not degrade to global-only. Failures are logged,
    not raised."""
    await _dispatch(title, message, level, category, instance_id, respect_routes=True)


# Strong refs to in-flight fire-and-forget sends, so the event loop doesn't GC a
# task mid-send (asyncio only holds a weak ref). Discarded when the task finishes.
_background_tasks: set[asyncio.Task] = set()


def dispatch_async(
    title: str, message: str, instance_id: int, level: str = "info", category: str = AVAILABILITY
) -> None:
    """Fire-and-forget ``send_notification`` for ``instance_id``: schedule the send as
    a background task so a caller on a latency-sensitive path (the agent WS ingest,
    the poll cycle) is never blocked by channel send latency (~10s/HTTP channel,
    SMTP). Delivery is best-effort — ``send_notification`` already logs every failure
    and never raises, so the task needs no result handling."""
    task = asyncio.create_task(send_notification(title, message, instance_id, level, category))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def send_test_notification(channel: str | None = None) -> list[ChannelResult]:
    """Send a test message and report per-channel status (for the Settings UI).

    Bypasses subscriptions (a test proves connectivity, independent of routing).
    With ``channel`` set, only that channel is tested.
    """
    # Emoji-prefixed like real alert titles, so the Test button exercises the same
    # Unicode-encoding path a production alert takes (it previously did not).
    results = await _dispatch(
        "✅ Orbit test notification",
        "If you can read this, Orbit notifications are working.",
        "info",
        AVAILABILITY,
        None,
        respect_routes=False,
    )
    if channel is not None:
        return [r for r in results if r.channel == channel]
    return results
