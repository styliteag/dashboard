"""Truth-table tests for the confidence model (probe → ping/http checks)."""

from __future__ import annotations

from app.checks.confidence import probe_checks
from app.checks.models import CheckState
from app.probe import ProbeResult


def _by_key(checks):
    return {c.key: c for c in checks}


def test_no_probe_emits_nothing() -> None:
    assert probe_checks(agent_fresh=False, probe=None) == []
    assert probe_checks(agent_fresh=True, probe=ProbeResult()) == []


def test_both_up_are_ok() -> None:
    p = ProbeResult(icmp_up=True, http_up=True, rtt_ms=3.2, http_status=200)
    checks = _by_key(probe_checks(agent_fresh=False, probe=p))
    assert checks["ping"].state == int(CheckState.OK)
    assert checks["http"].state == int(CheckState.OK)


def test_icmp_down_no_confirmed_up_is_crit() -> None:
    # agent stale + ICMP down + nothing says up → confirmed down.
    p = ProbeResult(icmp_up=False)
    checks = _by_key(probe_checks(agent_fresh=False, probe=p))
    assert checks["ping"].state == int(CheckState.CRIT)
    assert "http" not in checks  # http not probed (bare host)


def test_icmp_down_but_agent_fresh_is_warn() -> None:
    # Box is pushing telemetry, yet ICMP fails → suspect the target, not the box.
    p = ProbeResult(icmp_up=False)
    checks = _by_key(probe_checks(agent_fresh=True, probe=p))
    assert checks["ping"].state == int(CheckState.WARN)


def test_http_down_but_icmp_up_is_warn() -> None:
    # Box answers ICMP (alive) but web service is down → degraded, not an outage.
    p = ProbeResult(icmp_up=True, http_up=False, rtt_ms=2.0, http_status=None)
    checks = _by_key(probe_checks(agent_fresh=False, probe=p))
    assert checks["ping"].state == int(CheckState.OK)
    assert checks["http"].state == int(CheckState.WARN)


def test_both_down_no_confirmed_up_is_crit() -> None:
    p = ProbeResult(icmp_up=False, http_up=False)
    checks = _by_key(probe_checks(agent_fresh=False, probe=p))
    assert checks["ping"].state == int(CheckState.CRIT)
    assert checks["http"].state == int(CheckState.CRIT)


def test_http_only_down_with_fresh_agent_is_warn() -> None:
    # Bare-URL target with no ICMP axis; agent fresh → http failure capped at WARN.
    p = ProbeResult(icmp_up=None, http_up=False, http_status=503)
    checks = _by_key(probe_checks(agent_fresh=True, probe=p))
    assert "ping" not in checks
    assert checks["http"].state == int(CheckState.WARN)
    assert "503" in checks["http"].summary
