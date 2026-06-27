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
)


@pytest.mark.asyncio
async def test_dispatch_covers_all_channels_and_skips_unconfigured(monkeypatch) -> None:
    monkeypatch.setattr(notifier, "effective_settings", lambda: _EMPTY)
    results = await notifier.send_test_notification()
    assert {r.channel for r in results} == {"webhook", "telegram", "ntfy", "mattermost"}
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

    results = {r.channel: r for r in await notifier.send_test_notification()}
    assert results["mattermost"].status == "sent"
    assert posted["url"] == "https://mm.example.com/hooks/abc"
    assert "text" in posted["json"]


def test_mattermost_is_secret_setting() -> None:
    d = EDITABLE["notify_mattermost_url"]
    assert d.is_secret is True
    assert d.group == "Notifications"
    assert d.type == "str"
