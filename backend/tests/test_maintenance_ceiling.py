"""Tests for the maintenance ceiling (cap checks at WARN)."""

from __future__ import annotations

from app.checks.maintenance import apply_maintenance
from app.checks.models import CheckState, ServiceCheck


def _checks() -> list[ServiceCheck]:
    return [
        ServiceCheck(key="memory", state=int(CheckState.OK), summary="ok"),
        ServiceCheck(key="ipsec.tunnel:a", state=int(CheckState.CRIT), summary="down"),
        ServiceCheck(key="cpu", state=int(CheckState.WARN), summary="warn"),
    ]


def test_noop_when_not_in_maintenance() -> None:
    checks = _checks()
    assert apply_maintenance(checks, False) is checks


def test_caps_crit_to_warn_and_adds_banner() -> None:
    out = apply_maintenance(_checks(), True)
    assert out[0].key == "maintenance" and out[0].state == int(CheckState.WARN)
    by_key = {c.key: c for c in out}
    assert by_key["ipsec.tunnel:a"].state == int(CheckState.WARN)
    assert "(maintenance)" in by_key["ipsec.tunnel:a"].summary
    # OK/WARN are untouched (ceiling, not floor — OK does not become yellow).
    assert by_key["memory"].state == int(CheckState.OK)
    assert by_key["cpu"].state == int(CheckState.WARN)


def test_all_ok_box_still_yellow_via_banner() -> None:
    ok_only = [ServiceCheck(key="memory", state=int(CheckState.OK), summary="ok")]
    out = apply_maintenance(ok_only, True)
    assert any(c.key == "maintenance" and c.state == int(CheckState.WARN) for c in out)


def test_does_not_mutate_input() -> None:
    checks = _checks()
    apply_maintenance(checks, True)
    assert checks[1].state == int(CheckState.CRIT)
