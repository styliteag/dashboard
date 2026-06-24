"""Tests for the shared online/offline decision (poller + hub + staleness watchdog)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.metrics.store import is_online

_NOW = datetime(2026, 6, 24, 12, 0, 0, tzinfo=timezone.utc)
_EARLIER = _NOW - timedelta(minutes=5)


def test_online_when_success_and_no_error() -> None:
    assert is_online(_NOW, None) is True


def test_online_when_success_newer_than_error() -> None:
    assert is_online(_NOW, _EARLIER) is True


def test_offline_when_error_newer_than_success() -> None:
    assert is_online(_EARLIER, _NOW) is False


def test_offline_when_never_succeeded() -> None:
    assert is_online(None, _NOW) is False


def test_offline_when_no_data_at_all() -> None:
    assert is_online(None, None) is False
