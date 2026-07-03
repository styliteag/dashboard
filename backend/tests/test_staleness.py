"""Tests for the agent-staleness overlay (gate helper + checks overlay).

A push instance whose agent has gone silent keeps serving its last-known
sub-states from the hub cache. The overlay turns that into honest output: an
explicit ``agent`` service (OK fresh / WARN stale) and a CRIT→WARN ceiling on
every other check while stale (a "down" verdict on stale data is a guess).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.checks.models import CheckState, ServiceCheck
from app.checks.staleness import apply_staleness, staleness_for
from app.poller.gate import agent_age_seconds

NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def _inst(*, agent_mode=True, last_seen=None, push_override=None):
    return SimpleNamespace(
        agent_mode=agent_mode,
        agent_last_seen=last_seen,
        push_interval_seconds=push_override,
    )


def _settings(push=30, stale=120):
    return SimpleNamespace(push_interval_seconds=push, agent_stale_seconds=stale)


# --- gate.agent_age_seconds -------------------------------------------------


def test_agent_age_seconds_none_when_never_seen() -> None:
    assert agent_age_seconds(NOW, None) is None


def test_agent_age_seconds_counts_from_last_seen() -> None:
    assert agent_age_seconds(NOW, NOW - timedelta(seconds=42)) == 42


def test_agent_age_seconds_tags_naive_as_utc() -> None:
    naive = (NOW - timedelta(seconds=10)).replace(tzinfo=None)
    assert agent_age_seconds(NOW, naive) == 10


# --- staleness_for ----------------------------------------------------------


def test_staleness_none_for_direct_instance() -> None:
    inst = _inst(agent_mode=False, last_seen=NOW - timedelta(seconds=9999))
    assert staleness_for(inst, _settings(), NOW) is None


def test_staleness_none_when_agent_never_reported() -> None:
    assert staleness_for(_inst(last_seen=None), _settings(), NOW) is None


def test_staleness_fresh_below_threshold() -> None:
    s = staleness_for(_inst(last_seen=NOW - timedelta(seconds=10)), _settings(), NOW)
    assert s is not None
    assert s.stale is False
    assert s.age_seconds == 10
    assert s.threshold == 120  # max(120, 4*30)


def test_staleness_stale_above_threshold() -> None:
    s = staleness_for(_inst(last_seen=NOW - timedelta(seconds=1000)), _settings(), NOW)
    assert s is not None
    assert s.stale is True
    assert s.age_seconds == 1000


def test_staleness_threshold_scales_with_slow_push_override() -> None:
    # 4 * 300 = 1200 > floor 120 → a deliberately slow agent isn't flagged early.
    s = staleness_for(
        _inst(last_seen=NOW - timedelta(seconds=600), push_override=300),
        _settings(),
        NOW,
    )
    assert s is not None
    assert s.threshold == 1200
    assert s.stale is False  # 600s < 1200s tolerance


# --- apply_staleness --------------------------------------------------------


def _checks() -> list[ServiceCheck]:
    return [
        ServiceCheck(key="memory", state=int(CheckState.OK), summary="Memory 10% used (ok)"),
        ServiceCheck(key="ipsec.tunnel:a", state=int(CheckState.CRIT), summary="Tunnel a down"),
        ServiceCheck(key="cpu", state=int(CheckState.WARN), summary="CPU 96%"),
    ]


def test_apply_staleness_noop_when_none() -> None:
    checks = _checks()
    assert apply_staleness(checks, None) is checks


def test_apply_staleness_fresh_prepends_ok_agent_no_caps() -> None:
    s = staleness_for(_inst(last_seen=NOW - timedelta(seconds=5)), _settings(), NOW)
    out = apply_staleness(_checks(), s)
    assert out[0].key == "agent"
    assert out[0].state == int(CheckState.OK)
    # Original checks pass through unchanged.
    assert [c.state for c in out[1:]] == [
        int(CheckState.OK),
        int(CheckState.CRIT),
        int(CheckState.WARN),
    ]


def test_apply_staleness_stale_caps_crit_to_warn_and_adds_warn_agent() -> None:
    s = staleness_for(_inst(last_seen=NOW - timedelta(seconds=1000)), _settings(), NOW)
    out = apply_staleness(_checks(), s)
    agent = out[0]
    assert agent.key == "agent" and agent.state == int(CheckState.WARN)
    assert "1000s" in agent.summary

    by_key = {c.key: c for c in out}
    # CRIT tunnel capped to WARN with a stale note; OK/WARN untouched.
    assert by_key["ipsec.tunnel:a"].state == int(CheckState.WARN)
    assert "stale" in by_key["ipsec.tunnel:a"].summary.lower()
    assert by_key["memory"].state == int(CheckState.OK)
    assert by_key["cpu"].state == int(CheckState.WARN)


def test_apply_staleness_does_not_mutate_input() -> None:
    s = staleness_for(_inst(last_seen=NOW - timedelta(seconds=1000)), _settings(), NOW)
    checks = _checks()
    apply_staleness(checks, s)
    # Original CRIT check object is unchanged (immutability).
    assert checks[1].state == int(CheckState.CRIT)


# --- instance_response serialization wiring ---------------------------------


def _orm_like(**overrides):
    """An object carrying every InstanceResponse attribute (mirrors the ORM)."""
    base = dict(
        id=1,
        name="opn1",
        slug="opn1",
        base_url="https://opn1:4444",
        group_id=1,
        ssl_verify=True,
        gui_login_enabled=False,
        transport="push",
        device_type="opnsense",
        agent_mode=True,
        poll_interval_seconds=None,
        push_interval_seconds=None,
        ssh_enabled=False,
        ssh_port=9922,
        ssh_user="root",
        ssh_key_set=False,
        ssh_host_key_pinned=False,
        agent_last_seen=NOW - timedelta(seconds=5),
        location=None,
        notes=None,
        tags=None,
        last_success_at=NOW,
        last_error_at=None,
        last_error_message=None,
        created_at=NOW,
        updated_at=NOW,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_instance_response_marks_fresh_push_not_stale() -> None:
    from app.instances.schemas import instance_response

    out = instance_response(_orm_like(), _settings(), NOW)
    assert out.stale is False
    assert out.stale_seconds == 5


def test_instance_response_marks_silent_push_stale() -> None:
    from app.instances.schemas import instance_response

    out = instance_response(
        _orm_like(agent_last_seen=NOW - timedelta(seconds=1000)), _settings(), NOW
    )
    assert out.stale is True
    assert out.stale_seconds == 1000


def test_instance_response_direct_instance_never_stale() -> None:
    from app.instances.schemas import instance_response

    out = instance_response(
        _orm_like(agent_mode=False, transport="direct", agent_last_seen=None),
        _settings(),
        NOW,
    )
    assert out.stale is False
    assert out.stale_seconds is None


def test_instance_response_defaults_when_attrs_absent() -> None:
    """create/update return the bare ORM (no stale attr) → fields fall back to defaults."""
    from app.instances.schemas import InstanceResponse

    out = InstanceResponse.model_validate(_orm_like())  # no stale/stale_seconds attrs
    assert out.stale is False
    assert out.stale_seconds is None
