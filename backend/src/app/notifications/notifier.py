"""Notification dispatcher — sends alerts to all configured channels.

Channels (each optional): generic webhook, Telegram, ntfy, Mattermost. The
Mattermost webhook URL is editable in the Settings UI (secret); the others come
from the environment (``DASH_NOTIFY_*``). Values are read through
``effective_settings()`` so a DB override applies live. Failures are logged,
never raised.
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


async def _send_webhook(s, title: str, message: str, level: str) -> ChannelResult:  # noqa: ANN001
    url = getattr(s, "notify_webhook_url", "") or ""
    if not url:
        return ChannelResult("webhook", "skipped")
    reason = await _ssrf_block_reason(url)
    if reason:
        log.warning("notify.webhook.blocked", reason=reason)
        return ChannelResult("webhook", "failed", reason)
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
    reason = await _ssrf_block_reason(url)
    if reason:
        log.warning("notify.ntfy.blocked", reason=reason)
        return ChannelResult("ntfy", "failed", reason)
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


async def _dispatch(title: str, message: str, level: str) -> list[ChannelResult]:
    s = effective_settings()
    return [
        await _send_webhook(s, title, message, level),
        await _send_telegram(s, title, message, level),
        await _send_ntfy(s, title, message, level),
        await _send_mattermost(s, title, message, level),
        await _send_email(s, title, message, level),
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
