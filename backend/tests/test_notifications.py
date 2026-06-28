"""Tests for the notification dispatcher (channel wiring, routing filter, settings)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.notifications.notifier as notifier
from app.settings.registry import EDITABLE

_EMPTY = SimpleNamespace(
    notify_mattermost_url="",
    notify_telegram_token="",
    notify_telegram_chat_id="",
    notify_email_smtp_host="",
    notify_email_from="",
    notify_email_to="",
)


async def _resolve_public(_host: str) -> list[str]:
    """Stub for notifier._resolve: a public IP, so the SSRF guard allows the host
    without hitting real DNS."""
    return ["8.8.8.8"]


class _Client:
    """Minimal httpx.AsyncClient stand-in that records the last POST."""

    posted: dict[str, object] = {}

    def __init__(self, *a, **k) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a) -> None:
        return None

    async def post(self, url, json=None, **k):
        _Client.posted = {"url": url, "json": json}
        return SimpleNamespace(status_code=200)


@pytest.mark.asyncio
async def test_dispatch_covers_three_channels_and_skips_unconfigured(monkeypatch) -> None:
    monkeypatch.setattr(notifier, "effective_settings", lambda: _EMPTY)
    results = await notifier.send_test_notification()  # test path bypasses routing
    assert {r.channel for r in results} == {"mattermost", "telegram", "email"}
    assert all(r.status == "skipped" for r in results)  # nothing configured → no network


@pytest.mark.asyncio
async def test_dispatch_skips_channels_not_subscribed(monkeypatch) -> None:
    # Everything configured, but no channel is subscribed to the category → all
    # skipped as "not subscribed", and no network call is attempted.
    monkeypatch.setattr(notifier, "effective_settings", lambda: _all_configured())
    monkeypatch.setattr(notifier, "is_subscribed_live", lambda ch, cat: False)
    results = await notifier._dispatch("t", "m", "info", "cpu", respect_routes=True)
    assert {r.channel for r in results} == {"mattermost", "telegram", "email"}
    assert all(r.status == "skipped" and r.detail == "not subscribed" for r in results)


@pytest.mark.asyncio
async def test_dispatch_sends_only_to_subscribed_channel(monkeypatch) -> None:
    monkeypatch.setattr(notifier, "effective_settings", lambda: _all_configured())
    monkeypatch.setattr(notifier, "_resolve", _resolve_public)
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)
    # Only mattermost is subscribed to "cpu".
    monkeypatch.setattr(notifier, "is_subscribed_live", lambda ch, cat: ch == "mattermost")
    results = {
        r.channel: r for r in await notifier._dispatch("t", "m", "info", "cpu", respect_routes=True)
    }
    assert results["mattermost"].status == "sent"
    assert results["telegram"].status == "skipped"
    assert results["email"].status == "skipped"


def _all_configured() -> SimpleNamespace:
    return SimpleNamespace(
        notify_mattermost_url="https://mm.example.com/hooks/abc",
        notify_telegram_token="TOK",
        notify_telegram_chat_id="CHAT",
        notify_email_smtp_host="smtp.example.com",
        notify_email_smtp_port=587,
        notify_email_security="starttls",
        notify_email_from="orbit@example.com",
        notify_email_to="ops@example.com",
        notify_email_username="",
        notify_email_password="",
    )


@pytest.mark.asyncio
async def test_mattermost_attempts_when_configured(monkeypatch) -> None:
    cfg = SimpleNamespace(
        notify_mattermost_url="https://mm.example.com/hooks/abc",
        notify_telegram_token="",
        notify_telegram_chat_id="",
        notify_email_smtp_host="",
        notify_email_from="",
        notify_email_to="",
    )
    monkeypatch.setattr(notifier, "effective_settings", lambda: cfg)
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(notifier, "_resolve", _resolve_public)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["mattermost"].status == "sent"
    assert _Client.posted["url"] == "https://mm.example.com/hooks/abc"
    assert "text" in _Client.posted["json"]


@pytest.mark.asyncio
async def test_telegram_sends_plaintext_without_markdown(monkeypatch) -> None:
    """No parse_mode → a metacharacter in the content can never trigger a 400 drop."""
    cfg = SimpleNamespace(
        notify_mattermost_url="",
        notify_telegram_token="TOK",
        notify_telegram_chat_id="CHAT",
        notify_email_smtp_host="",
        notify_email_from="",
        notify_email_to="",
    )
    monkeypatch.setattr(notifier, "effective_settings", lambda: cfg)
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["telegram"].status == "sent"
    assert "parse_mode" not in _Client.posted["json"]
    assert "*" not in _Client.posted["json"]["text"]
    assert _Client.posted["json"]["text"].startswith("✅ Orbit test notification")


def test_mattermost_and_telegram_secret_settings() -> None:
    assert EDITABLE["notify_mattermost_url"].is_secret is True
    assert EDITABLE["notify_mattermost_url"].group == "Mattermost"
    # Telegram is now UI-editable like Mattermost: token secret, chat id plain.
    assert EDITABLE["notify_telegram_token"].is_secret is True
    assert EDITABLE["notify_telegram_token"].group == "Telegram"
    assert EDITABLE["notify_telegram_chat_id"].is_secret is False
    assert EDITABLE["notify_telegram_chat_id"].group == "Telegram"


def test_dropped_channels_are_gone() -> None:
    # webhook + ntfy were removed entirely — no settings, no senders.
    assert "notify_webhook_url" not in EDITABLE
    assert "notify_ntfy_url" not in EDITABLE
    assert not hasattr(notifier, "_send_webhook")
    assert not hasattr(notifier, "_send_ntfy")


@pytest.mark.asyncio
async def test_ssrf_guard_blocks_metadata_loopback_and_bad_scheme() -> None:
    assert await notifier._ssrf_block_reason("http://169.254.169.254/latest/meta-data/")
    assert await notifier._ssrf_block_reason("http://127.0.0.1:8080/hook")
    assert await notifier._ssrf_block_reason("https://[::1]/hook")
    assert await notifier._ssrf_block_reason("file:///etc/passwd")
    assert await notifier._ssrf_block_reason("ftp://example.com/x")


@pytest.mark.asyncio
async def test_ssrf_guard_allows_private_and_public() -> None:
    # Internal notification servers (self-hosted Mattermost) are legitimate.
    assert await notifier._ssrf_block_reason("http://10.20.1.198:4444/hook") is None
    assert await notifier._ssrf_block_reason("https://192.168.1.5/hook") is None
    assert await notifier._ssrf_block_reason("https://8.8.8.8/hook") is None


@pytest.mark.asyncio
async def test_mattermost_blocked_url_is_not_posted(monkeypatch) -> None:
    cfg = SimpleNamespace(
        notify_mattermost_url="http://169.254.169.254/hooks/abc",
        notify_telegram_token="",
        notify_telegram_chat_id="",
        notify_email_smtp_host="",
        notify_email_from="",
        notify_email_to="",
    )
    posted = {"called": False}

    class _Block(_Client):
        async def post(self, *a, **k):
            posted["called"] = True
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(notifier, "effective_settings", lambda: cfg)
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Block)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["mattermost"].status == "failed"
    assert posted["called"] is False  # never POSTed to the blocked target


def _email_cfg(**over) -> SimpleNamespace:
    base = dict(
        notify_mattermost_url="",
        notify_telegram_token="",
        notify_telegram_chat_id="",
        notify_email_smtp_host="smtp.example.com",
        notify_email_smtp_port=587,
        notify_email_security="starttls",
        notify_email_from="orbit@example.com",
        notify_email_to="ops@example.com, oncall@example.com",
        notify_email_username="orbit",
        notify_email_password="secret",
    )
    base.update(over)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_email_skipped_when_incomplete(monkeypatch) -> None:
    monkeypatch.setattr(notifier, "effective_settings", lambda: _email_cfg(notify_email_to=""))
    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["email"].status == "skipped"


@pytest.mark.asyncio
async def test_email_sends_when_configured(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_smtp_send(**kwargs) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(notifier, "effective_settings", lambda: _email_cfg())
    monkeypatch.setattr(notifier, "_smtp_send", _fake_smtp_send)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["email"].status == "sent"
    assert captured["host"] == "smtp.example.com"
    assert captured["recipients"] == ["ops@example.com", "oncall@example.com"]


@pytest.mark.asyncio
async def test_email_failure_is_reported_not_raised(monkeypatch) -> None:
    def _boom(**kwargs) -> None:
        raise OSError("connection refused")

    monkeypatch.setattr(notifier, "effective_settings", lambda: _email_cfg())
    monkeypatch.setattr(notifier, "_smtp_send", _boom)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["email"].status == "failed"
    assert "connection refused" in results["email"].detail


def test_email_password_is_secret_setting() -> None:
    assert EDITABLE["notify_email_password"].is_secret is True
    assert EDITABLE["notify_email_smtp_host"].is_secret is False


@pytest.mark.asyncio
async def test_single_channel_test_filters(monkeypatch) -> None:
    monkeypatch.setattr(notifier, "effective_settings", lambda: _EMPTY)
    results = await notifier.send_test_notification("email")
    assert {r.channel for r in results} == {"email"}
