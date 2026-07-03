"""Per-group notification-channel routing (group target replaces global).

DB-free in the house style — the override loader / sessionmaker are
monkeypatched; senders are spies capturing the settings object they receive.
Covers the adapter's delegation, the replace-vs-fallback dispatch, mute
precedence, the test-send bypass, fail-open loading and SSRF on group URLs.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.notifications.notifier as notifier
from app.notifications.channel_config import CHANNEL_FIELDS, CHANNELS, GroupChannelSettings

_GLOBAL = SimpleNamespace(
    notify_mattermost_url="https://global.example/hook",
    notify_mattermost_muted=False,
    notify_telegram_token="global-token",
    notify_telegram_chat_id="global-chat",
    notify_telegram_muted=False,
    notify_email_smtp_host="smtp.global",
    notify_email_from="global@example",
    notify_email_to="ops@example",
    notify_email_muted=False,
)


def _capture_senders(seen: dict[str, object]):
    """Replacement _CHANNEL_SENDERS capturing the settings object per channel."""

    def make(name: str):
        async def _s(s, _title, _message, _level):  # noqa: ANN001
            seen[name] = s
            return notifier.ChannelResult(name, "sent")

        return _s

    return tuple((n, make(n)) for n in CHANNELS)


# --- adapter ------------------------------------------------------------------


def test_adapter_serves_channel_fields_and_delegates_rest() -> None:
    cfg = {"url": "https://group.example/hook"}
    s = GroupChannelSettings(_GLOBAL, "mattermost", cfg)
    assert s.notify_mattermost_url == "https://group.example/hook"
    # foreign channel + mute flags delegate to the global object
    assert s.notify_telegram_token == "global-token"
    assert s.notify_mattermost_muted is False


def test_adapter_missing_field_is_empty_not_global() -> None:
    # A group email config without a username must NOT inherit the global
    # username — the group target is a full replacement for its channel.
    s = GroupChannelSettings(_GLOBAL, "email", {"smtp_host": "smtp.group"})
    assert s.notify_email_smtp_host == "smtp.group"
    assert s.notify_email_username == ""


def test_channel_fields_cover_all_sender_attrs() -> None:
    # Every channel spec maps to notify_* names; keep spec and senders in sync.
    for channel in CHANNELS:
        for field in CHANNEL_FIELDS[channel]:
            assert field.attr.startswith("notify_")


# --- dispatch: replace vs fallback ------------------------------------------------


@pytest.mark.asyncio
async def test_group_override_replaces_global_for_its_channel(monkeypatch) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(notifier, "effective_settings", lambda: _GLOBAL)
    monkeypatch.setattr(notifier, "is_on_live", lambda c, k, i: True)
    monkeypatch.setattr(notifier, "_CHANNEL_SENDERS", _capture_senders(seen))

    async def _overrides(_iid: int) -> dict:
        return {"mattermost": {"url": "https://group.example/hook"}}

    monkeypatch.setattr(notifier, "_group_channel_overrides", _overrides)

    await notifier._dispatch("t", "m", "info", "cpu", 1, respect_routes=True)
    assert seen["mattermost"].notify_mattermost_url == "https://group.example/hook"
    # unconfigured kinds fall back to the untouched global object
    assert seen["telegram"] is _GLOBAL
    assert seen["email"] is _GLOBAL


@pytest.mark.asyncio
async def test_global_mute_beats_group_override(monkeypatch) -> None:
    seen: dict[str, object] = {}
    muted = SimpleNamespace(**{**_GLOBAL.__dict__, "notify_mattermost_muted": True})
    monkeypatch.setattr(notifier, "effective_settings", lambda: muted)
    monkeypatch.setattr(notifier, "is_on_live", lambda c, k, i: True)
    monkeypatch.setattr(notifier, "_CHANNEL_SENDERS", _capture_senders(seen))

    async def _overrides(_iid: int) -> dict:
        return {"mattermost": {"url": "https://group.example/hook"}}

    monkeypatch.setattr(notifier, "_group_channel_overrides", _overrides)

    results = {
        r.channel: r
        for r in await notifier._dispatch("t", "m", "info", "cpu", 1, respect_routes=True)
    }
    assert results["mattermost"].status == "skipped"
    assert results["mattermost"].detail == "muted"
    assert "mattermost" not in seen  # group target muted too


@pytest.mark.asyncio
async def test_test_send_never_loads_group_overrides(monkeypatch) -> None:
    monkeypatch.setattr(notifier, "effective_settings", lambda: _GLOBAL)
    monkeypatch.setattr(notifier, "_CHANNEL_SENDERS", _capture_senders({}))

    async def _boom(_iid: int) -> dict:
        raise AssertionError("loader must not run for instance_id=None")

    monkeypatch.setattr(notifier, "_group_channel_overrides", _boom)
    await notifier.send_test_notification()  # instance_id=None → global only


# --- loader fail-open --------------------------------------------------------------


@pytest.mark.asyncio
async def test_loader_fails_open_to_global(monkeypatch) -> None:
    def _broken_sessionmaker():
        raise RuntimeError("db down")

    monkeypatch.setattr(notifier, "get_sessionmaker", _broken_sessionmaker)
    assert await notifier._group_channel_overrides(1) == {}


# --- SSRF applies to group URLs -----------------------------------------------------


@pytest.mark.asyncio
async def test_group_mattermost_url_passes_ssrf_guard(monkeypatch) -> None:
    # The unchanged sender reads the group URL and runs the same SSRF check —
    # a metadata-service URL in a group config must fail, not POST.
    posted: list[str] = []

    class _Client:
        def __init__(self, *a, **k) -> None:  # noqa: ANN002, ANN003
            pass

        async def __aenter__(self):  # noqa: ANN204
            return self

        async def __aexit__(self, *a) -> None:  # noqa: ANN002
            return None

        async def post(self, url, json=None, **k):  # noqa: ANN001, ANN003
            posted.append(url)
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(notifier.httpx, "AsyncClient", _Client)
    s = GroupChannelSettings(_GLOBAL, "mattermost", {"url": "http://169.254.169.254/latest"})
    result = await notifier._send_mattermost(s, "t", "m", "info")
    assert result.status == "failed"
    assert posted == []
