"""Tests for the shared online/offline decision (poller + hub + staleness watchdog)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.metrics.store import is_online, to_rate

_NOW = datetime(2026, 6, 24, 12, 0, 0, tzinfo=UTC)
_EARLIER = _NOW - timedelta(minutes=5)


def _pt(offset_s: int, value: float) -> dict:
    return {"ts": (_NOW + timedelta(seconds=offset_s)).isoformat(), "value": value}


def test_to_rate_basic() -> None:
    rate = to_rate([_pt(0, 100), _pt(10, 300), _pt(20, 350)])
    assert [round(p["value"], 3) for p in rate] == [20.0, 5.0]  # bytes/sec
    assert rate[0]["ts"] == _pt(10, 0)["ts"]  # rate stamped at the later point


def test_to_rate_clamps_counter_reset() -> None:
    # reboot resets the counter → negative delta → 0, not a huge spike
    rate = to_rate([_pt(0, 1_000_000), _pt(10, 50)])
    assert rate == [{"ts": _pt(10, 0)["ts"], "value": 0.0}]


def test_to_rate_short_series() -> None:
    assert to_rate([]) == []
    assert to_rate([_pt(0, 5)]) == []


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
