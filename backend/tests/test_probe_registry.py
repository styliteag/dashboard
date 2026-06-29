"""Debounce reducer + registry tests (flap protection)."""

from __future__ import annotations

from app.probe import ProbeResult
from app.probe.registry import AxisState, ProbeRegistry, reduce_axis


def test_success_resets_immediately() -> None:
    s = reduce_axis(AxisState(up=False, fail_streak=5), raw_up=True, threshold=3)
    assert s.up is True and s.fail_streak == 0


def test_inapplicable_axis_resets_to_no_signal() -> None:
    # raw_up=None means the axis doesn't apply to this target (bare-host ping_url has
    # no HTTP axis) — it must NOT carry a stale value forward, it resets to None.
    assert reduce_axis(AxisState(up=True, fail_streak=2), raw_up=None, threshold=3) == AxisState()


def test_down_only_after_threshold_consecutive_fails() -> None:
    s = AxisState()  # undecided
    s = reduce_axis(s, raw_up=False, threshold=3)
    assert s.up is None and s.fail_streak == 1  # one blip — not down yet
    s = reduce_axis(s, raw_up=False, threshold=3)
    assert s.up is None and s.fail_streak == 2
    s = reduce_axis(s, raw_up=False, threshold=3)
    assert s.up is False and s.fail_streak == 3  # now confirmed down


def test_was_up_holds_until_threshold_then_flips() -> None:
    s = AxisState(up=True, fail_streak=0)
    s = reduce_axis(s, raw_up=False, threshold=3)
    assert s.up is True  # single drop — still up
    s = reduce_axis(s, raw_up=False, threshold=3)
    assert s.up is True  # second drop — still up
    s = reduce_axis(s, raw_up=False, threshold=3)
    assert s.up is False  # third — flip


def test_threshold_one_flips_on_first_fail() -> None:
    s = reduce_axis(AxisState(up=True), raw_up=False, threshold=1)
    assert s.up is False


def test_registry_exposes_debounced_view() -> None:
    reg = ProbeRegistry()
    assert reg.get(7) is None  # never probed
    # Two failures with threshold 3 → still not down (holds undecided / last rtt).
    reg.update(7, ProbeResult(icmp_up=True, rtt_ms=2.0), threshold=3)
    reg.update(7, ProbeResult(icmp_up=False), threshold=3)
    view = reg.get(7)
    assert view is not None
    assert view.icmp_up is True  # one fail after an up → debounced still up
    # Drive past threshold.
    reg.update(7, ProbeResult(icmp_up=False), threshold=3)
    reg.update(7, ProbeResult(icmp_up=False), threshold=3)
    assert reg.get(7).icmp_up is False


def test_registry_inapplicable_axis_stays_none() -> None:
    # An instance whose ping_url is a bare host has no HTTP axis: even after a prior
    # URL probe set http up, switching to None must drop it (no phantom http check).
    reg = ProbeRegistry()
    reg.update(3, ProbeResult(icmp_up=True, http_up=True, http_status=200), threshold=3)
    reg.update(3, ProbeResult(icmp_up=True, http_up=None), threshold=3)
    view = reg.get(3)
    assert view.icmp_up is True
    assert view.http_up is None


def test_registry_forget() -> None:
    reg = ProbeRegistry()
    reg.update(1, ProbeResult(icmp_up=True), threshold=3)
    reg.forget(1)
    assert reg.get(1) is None
