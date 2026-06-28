"""Tests for the notification dispatcher (channel wiring + Mattermost setting)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.notifications.notifier as notifier
from app.settings.registry import EDITABLE

_EMPTY = SimpleNamespace(
    notify_webhook_url="",
    notify_telegram_token="",
    notify_telegram_chat_id="",
    notify_ntfy_url="",
    notify_mattermost_url="",
    notify_email_smtp_host="",
    notify_email_from="",
    notify_email_to="",
)


async def _resolve_public(_host: str) -> list[str]:
    """Stub for notifier._resolve: a public IP, so the SSRF guard allows the host
    without hitting real DNS."""
    return ["8.8.8.8"]


@pytest.mark.asyncio
async def test_dispatch_covers_all_channels_and_skips_unconfigured(monkeypatch) -> None:
    monkeypatch.setattr(notifier, "effective_settings", lambda: _EMPTY)
    results = await notifier.send_test_notification()
    assert {r.channel for r in results} == {"webhook", "telegram", "ntfy", "mattermost", "email"}
    assert all(r.status == "skipped" for r in results)  # nothing configured → no network


@pytest.mark.asyncio
async def test_mattermost_attempts_when_configured(monkeypatch) -> None:
    cfg = SimpleNamespace(
        notify_webhook_url="",
        notify_telegram_token="",
        notify_telegram_chat_id="",
        notify_ntfy_url="",
        notify_mattermost_url="https://mm.example.com/hooks/abc",
    )
    posted: dict[str, object] = {}

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, url, json=None, **k):
            posted["url"] = url
            posted["json"] = json
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(notifier, "effective_settings", lambda: cfg)
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)
    # Isolate from real DNS: pretend the host resolves to a public IP (the SSRF
    # guard resolves hostnames, and mm.example.com does not resolve in CI).
    monkeypatch.setattr(notifier, "_resolve", _resolve_public)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["mattermost"].status == "sent"
    assert posted["url"] == "https://mm.example.com/hooks/abc"
    assert "text" in posted["json"]


def test_mattermost_is_secret_setting() -> None:
    d = EDITABLE["notify_mattermost_url"]
    assert d.is_secret is True
    assert d.group == "Notifications"
    assert d.type == "str"


def _email_cfg(**over) -> SimpleNamespace:
    base = dict(
        notify_webhook_url="",
        notify_telegram_token="",
        notify_telegram_chat_id="",
        notify_ntfy_url="",
        notify_mattermost_url="",
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
    # Host set but no recipients → not "configured" → skipped, never connects.
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
    assert captured["port"] == 587
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


def _ntfy_cfg(url: str) -> SimpleNamespace:
    return SimpleNamespace(
        notify_webhook_url="",
        notify_telegram_token="",
        notify_telegram_chat_id="",
        notify_ntfy_url=url,
        notify_mattermost_url="",
    )


@pytest.mark.asyncio
async def test_ntfy_uses_json_publish_to_server_root(monkeypatch) -> None:
    """Title (emoji) must ride in the UTF-8 JSON body, POSTed to the server root."""
    posted: dict[str, object] = {}

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, url, json=None, **k):
            posted["url"] = url
            posted["json"] = json
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(
        notifier, "effective_settings", lambda: _ntfy_cfg("https://ntfy.sh/mytopic")
    )
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["ntfy"].status == "sent"
    # POSTed to the server ROOT, not the topic URL (the trap: topic URL would
    # publish the literal JSON as the message text).
    assert posted["url"] == "https://ntfy.sh"
    assert posted["json"]["topic"] == "mytopic"
    assert posted["json"]["title"].startswith("✅")  # emoji carried, not rejected
    assert posted["json"]["priority"] == 2  # info → low


@pytest.mark.asyncio
async def test_ntfy_without_topic_fails_without_posting(monkeypatch) -> None:
    called = {"posted": False}

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, *a, **k):
            called["posted"] = True
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(notifier, "effective_settings", lambda: _ntfy_cfg("https://ntfy.sh"))
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["ntfy"].status == "failed"
    assert called["posted"] is False  # never POST JSON to a topic-less root


@pytest.mark.asyncio
async def test_telegram_sends_plaintext_without_markdown(monkeypatch) -> None:
    """No parse_mode → a metacharacter in the content can never trigger a 400 drop."""
    cfg = SimpleNamespace(
        notify_webhook_url="",
        notify_telegram_token="TOK",
        notify_telegram_chat_id="CHAT",
        notify_ntfy_url="",
        notify_mattermost_url="",
    )
    posted: dict[str, object] = {}

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, url, json=None, **k):
            posted["url"] = url
            posted["json"] = json
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(notifier, "effective_settings", lambda: cfg)
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["telegram"].status == "sent"
    assert "parse_mode" not in posted["json"]  # plaintext: no parser to choke on
    assert "*" not in posted["json"]["text"]  # no Markdown emphasis wrapping
    assert posted["json"]["text"].startswith("✅ Orbit test notification")


@pytest.mark.asyncio
async def test_ssrf_guard_blocks_metadata_loopback_and_bad_scheme() -> None:
    # IP literals → no DNS, deterministic. 169.254.169.254 is link-local (metadata).
    assert await notifier._ssrf_block_reason("http://169.254.169.254/latest/meta-data/")
    assert await notifier._ssrf_block_reason("http://127.0.0.1:8080/hook")
    assert await notifier._ssrf_block_reason("https://[::1]/hook")
    assert await notifier._ssrf_block_reason("file:///etc/passwd")
    assert await notifier._ssrf_block_reason("ftp://example.com/x")


@pytest.mark.asyncio
async def test_ssrf_guard_allows_private_and_public() -> None:
    # Internal notification servers (self-hosted Mattermost/ntfy) are legitimate.
    assert await notifier._ssrf_block_reason("http://10.20.1.198:4444/hook") is None
    assert await notifier._ssrf_block_reason("https://192.168.1.5/hook") is None
    assert await notifier._ssrf_block_reason("https://8.8.8.8/hook") is None


@pytest.mark.asyncio
async def test_mattermost_blocked_url_is_not_posted(monkeypatch) -> None:
    cfg = SimpleNamespace(
        notify_webhook_url="",
        notify_telegram_token="",
        notify_telegram_chat_id="",
        notify_ntfy_url="",
        notify_mattermost_url="http://169.254.169.254/hooks/abc",
    )
    posted = {"called": False}

    class _Client:
        def __init__(self, *a, **k) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a) -> None:
            return None

        async def post(self, *a, **k):
            posted["called"] = True
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(notifier, "effective_settings", lambda: cfg)
    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["mattermost"].status == "failed"
    assert posted["called"] is False  # never POSTed to the blocked target


def test_split_ntfy_url_handles_subpath_and_trailing_slash() -> None:
    assert notifier._split_ntfy_url("https://ntfy.sh/mytopic") == ("https://ntfy.sh", "mytopic")
    assert notifier._split_ntfy_url("https://ntfy.sh/mytopic/") == ("https://ntfy.sh", "mytopic")
    assert notifier._split_ntfy_url("https://x.test/ntfy/alerts") == (
        "https://x.test/ntfy",
        "alerts",
    )
    assert notifier._split_ntfy_url("https://ntfy.sh") == ("", "")
