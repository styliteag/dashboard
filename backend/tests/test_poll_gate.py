"""Pure due/staleness gating for the per-instance poll/push scheduler."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.poller.gate import (
    effective_interval,
    is_due,
    is_stale,
    last_attempt,
    stale_threshold,
)

NOW = datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC)


def _ago(seconds: int, *, naive: bool = False) -> datetime:
    ts = NOW - timedelta(seconds=seconds)
    return ts.replace(tzinfo=None) if naive else ts


# --- effective_interval ------------------------------------------------------


def test_effective_interval_override_wins():
    assert effective_interval(60, 30) == 60


def test_effective_interval_none_falls_back():
    assert effective_interval(None, 30) == 30


def test_effective_interval_zero_falls_back():
    # A bogus 0 override must never become a 0s interval (hot loop).
    assert effective_interval(0, 30) == 30


# --- last_attempt ------------------------------------------------------------


def test_last_attempt_picks_newest():
    success = _ago(100)
    error = _ago(10)
    assert last_attempt(success, error) == error


def test_last_attempt_both_none():
    assert last_attempt(None, None) is None


def test_last_attempt_tags_naive_db_value():
    # MariaDB reads back naive UTC; the result must be tz-aware for arithmetic.
    assert last_attempt(_ago(10, naive=True), None).tzinfo is not None


# --- is_due ------------------------------------------------------------------


def test_is_due_never_polled():
    assert is_due(NOW, None, None, 30) is True


def test_is_due_recent_success_not_yet_due():
    assert is_due(NOW, _ago(10), None, 30) is False


def test_is_due_old_success_due():
    assert is_due(NOW, _ago(40), None, 30) is True


def test_is_due_failing_box_gates_on_last_error():
    # last_success_at is ancient but it just errored 5s ago — don't hammer it.
    assert is_due(NOW, _ago(9000), _ago(5), 30) is False


def test_is_due_handles_naive_timestamps():
    assert is_due(NOW, _ago(40, naive=True), None, 30) is True


# --- stale_threshold ---------------------------------------------------------


def test_stale_threshold_floor_for_default_push():
    # 4 * 30 == 120 == base floor — fast agents keep the generous floor.
    assert stale_threshold(None, 30, 120) == 120


def test_stale_threshold_scales_with_slow_push():
    # A 300s push agent must not be flagged stale at the 120s floor.
    assert stale_threshold(300, 30, 120) == 1200


def test_stale_threshold_override_drives_scaling():
    assert stale_threshold(600, 30, 120) == 2400


# --- is_stale ----------------------------------------------------------------


def test_is_stale_no_push_yet():
    assert is_stale(NOW, None, 120) is False


def test_is_stale_recent_push_ok():
    assert is_stale(NOW, _ago(60), 120) is False


def test_is_stale_silent_too_long():
    assert is_stale(NOW, _ago(200), 120) is True


def test_is_stale_handles_naive_timestamp():
    assert is_stale(NOW, _ago(200, naive=True), 120) is True


# ignore_before (backend boot time) floors the silence clock. Regression
# 2026-07-12: a 5-minute container outage flagged all 70 push instances
# offline on the first tick after restart — before any agent could
# reconnect — producing a 140-message offline/recovered storm in Mattermost.


def test_is_stale_ignores_backend_downtime():
    # Agent silent for 10 min, but the backend booted 30s ago: silence is
    # counted from boot, so the agent gets its full threshold to reconnect.
    assert is_stale(NOW, _ago(600), 120, _ago(30)) is False


def test_is_stale_fires_when_silent_past_threshold_after_boot():
    # Backend has been up longer than the threshold and the agent still has
    # not reported: genuinely dead agents alert threshold seconds after boot.
    assert is_stale(NOW, _ago(600), 120, _ago(300)) is True


def test_is_stale_old_boot_does_not_mask_real_silence():
    # Steady state (boot long in the past): the floor is inert and real
    # silence is measured from agent_last_seen as before.
    assert is_stale(NOW, _ago(200), 120, _ago(10_000)) is True


def test_is_stale_no_floor_keeps_old_behavior():
    assert is_stale(NOW, _ago(200), 120, None) is True
