"""Tests for the probe scheduler's maintenance auto-clear decision."""

from __future__ import annotations

from app.poller.scheduler import _probe_confirms_up
from app.probe import ProbeResult


def test_probe_confirms_up_decision() -> None:
    assert _probe_confirms_up(None) is False
    assert _probe_confirms_up(ProbeResult()) is False  # unprobed
    assert _probe_confirms_up(ProbeResult(icmp_up=True)) is True
    assert _probe_confirms_up(ProbeResult(http_up=True)) is True
    assert _probe_confirms_up(ProbeResult(icmp_up=False, http_up=False)) is False
    # A pending/undecided axis (None) is not a positive confirmation.
    assert _probe_confirms_up(ProbeResult(icmp_up=None, http_up=None)) is False
