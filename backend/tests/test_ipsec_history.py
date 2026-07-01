"""Tests for the IPsec tunnel state-change diff (pure, DB-free).

``diff_ipsec`` compares two successive ``IPsecServiceStatus`` snapshots of one
instance and returns the transitions worth remembering: Phase-1 up/down,
Phase-2 installed-count changes, and per-child ping ok/fail.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.ipsec.event_store import record_tunnel_events
from app.ipsec.history import TunnelEvent, diff_ipsec
from app.xsense.schemas import IPsecChild, IPsecServiceStatus, IPsecTunnel


def _status(*tunnels: IPsecTunnel) -> IPsecServiceStatus:
    return IPsecServiceStatus(running=True, tunnels=list(tunnels))


def _tunnel(
    tid: str = "con1",
    phase1: str = "established",
    p2_up: int = 1,
    p2_total: int = 1,
    children: list[IPsecChild] | None = None,
) -> IPsecTunnel:
    return IPsecTunnel(
        id=tid,
        phase1_status=phase1,
        phase2_up=p2_up,
        phase2_total=p2_total,
        children=children or [],
    )


# --- no prior state ----------------------------------------------------------


def test_none_prev_yields_no_events() -> None:
    """First push for an instance has no baseline → never spams down→up on startup."""
    assert diff_ipsec(None, _status(_tunnel())) == []


def test_unchanged_yields_no_events() -> None:
    snap = _status(_tunnel())
    assert diff_ipsec(snap, _status(_tunnel())) == []


def test_new_tunnel_is_ignored() -> None:
    """A tunnel that appears with no prior end gets no event (no baseline to diff)."""
    assert diff_ipsec(_status(), _status(_tunnel())) == []


# --- phase 1 -----------------------------------------------------------------


def test_phase1_down() -> None:
    prev = _status(_tunnel(phase1="established"))
    new = _status(_tunnel(phase1="down"))
    events = diff_ipsec(prev, new)
    assert events == [
        TunnelEvent("con1", "", "phase1_down", "established", "down"),
    ]


def test_phase1_up() -> None:
    prev = _status(_tunnel(phase1="connecting"))
    new = _status(_tunnel(phase1="established"))
    assert diff_ipsec(prev, new) == [
        TunnelEvent("con1", "", "phase1_up", "connecting", "established"),
    ]


def test_phase1_string_change_without_up_down_flip() -> None:
    """down → connecting: both 'not up' but a meaningful status change worth logging."""
    prev = _status(_tunnel(phase1="down"))
    new = _status(_tunnel(phase1="connecting"))
    assert diff_ipsec(prev, new) == [
        TunnelEvent("con1", "", "phase1_changed", "down", "connecting"),
    ]


# --- phase 2 -----------------------------------------------------------------


def test_phase2_count_change() -> None:
    prev = _status(_tunnel(p2_up=2, p2_total=2))
    new = _status(_tunnel(p2_up=1, p2_total=2))
    assert diff_ipsec(prev, new) == [
        TunnelEvent("con1", "", "phase2_changed", "2/2", "1/2"),
    ]


# --- ping --------------------------------------------------------------------


def _child(name: str = "c1", ping: str = "none") -> IPsecChild:
    return IPsecChild(name=name, ping_state=ping)


def test_ping_fail() -> None:
    prev = _status(_tunnel(children=[_child(ping="ok")]))
    new = _status(_tunnel(children=[_child(ping="fail")]))
    assert diff_ipsec(prev, new) == [
        TunnelEvent("con1", "c1", "ping_fail", "ok", "fail"),
    ]


def test_ping_ok() -> None:
    prev = _status(_tunnel(children=[_child(ping="fail")]))
    new = _status(_tunnel(children=[_child(ping="ok")]))
    assert diff_ipsec(prev, new) == [
        TunnelEvent("con1", "c1", "ping_ok", "fail", "ok"),
    ]


def test_ping_error_maps_to_fail_keeps_exact_value() -> None:
    prev = _status(_tunnel(children=[_child(ping="ok")]))
    new = _status(_tunnel(children=[_child(ping="error")]))
    assert diff_ipsec(prev, new) == [
        TunnelEvent("con1", "c1", "ping_fail", "ok", "error"),
    ]


def test_ping_transition_into_none_is_ignored() -> None:
    """Monitor removed / no data → not a tunnel-health event, skip the noise."""
    prev = _status(_tunnel(children=[_child(ping="ok")]))
    new = _status(_tunnel(children=[_child(ping="none")]))
    assert diff_ipsec(prev, new) == []


def test_unmatched_child_is_ignored() -> None:
    """A child with no prior counterpart has no baseline → no ping event."""
    prev = _status(_tunnel(children=[]))
    new = _status(_tunnel(children=[_child(ping="fail")]))
    assert diff_ipsec(prev, new) == []


# --- combined ----------------------------------------------------------------


def test_multiple_events_in_one_diff() -> None:
    prev = _status(_tunnel(phase1="established", p2_up=2, p2_total=2, children=[_child(ping="ok")]))
    new = _status(_tunnel(phase1="down", p2_up=0, p2_total=2, children=[_child(ping="fail")]))
    events = diff_ipsec(prev, new)
    assert TunnelEvent("con1", "", "phase1_down", "established", "down") in events
    assert TunnelEvent("con1", "", "phase2_changed", "2/2", "0/2") in events
    assert TunnelEvent("con1", "c1", "ping_fail", "ok", "fail") in events
    assert len(events) == 3


def test_two_tunnels_diff_independently() -> None:
    prev = _status(_tunnel("con1", phase1="established"), _tunnel("con2", phase1="established"))
    new = _status(_tunnel("con1", phase1="down"), _tunnel("con2", phase1="established"))
    assert diff_ipsec(prev, new) == [
        TunnelEvent("con1", "", "phase1_down", "established", "down"),
    ]


# --- duplicate Phase-2 note appearing / clearing -----------------------------


def _dup_child(persistent: bool, dup_count: int = 2) -> IPsecChild:
    return IPsecChild(
        name="c1",
        local_ts="10.1.1.0/24",
        remote_ts="10.2.2.0/24",
        state="INSTALLED",
        dup_count=dup_count,
        phase2_dup_persistent=persistent,
    )


def test_dup_persistent_false_to_true_emits_on() -> None:
    prev = _status(_tunnel(children=[_dup_child(False, dup_count=1)]))
    new = _status(_tunnel(children=[_dup_child(True, dup_count=2)]))
    events = diff_ipsec(prev, new)
    assert [e.event_type for e in events] == ["phase2_dup_on"]
    e = events[0]
    assert e.child_name == "c1"
    assert e.old_value == "10.1.1.0/24 → 10.2.2.0/24"  # selector pair
    assert e.new_value == "2× SAs"


def test_dup_persistent_true_to_false_emits_off() -> None:
    prev = _status(_tunnel(children=[_dup_child(True)]))
    new = _status(_tunnel(children=[_dup_child(False, dup_count=1)]))
    events = diff_ipsec(prev, new)
    assert [e.event_type for e in events] == ["phase2_dup_off"]
    assert events[0].new_value == "resolved"


def test_dup_persistent_unchanged_emits_nothing() -> None:
    # both True (still duplicated) and both False (never duplicated) → no event
    on = _status(_tunnel(children=[_dup_child(True)]))
    assert diff_ipsec(on, _status(_tunnel(children=[_dup_child(True)]))) == []
    off = _status(_tunnel(children=[_dup_child(False, dup_count=1)]))
    assert diff_ipsec(off, _status(_tunnel(children=[_dup_child(False, dup_count=1)]))) == []


# --- children sharing a name but different selectors (multi-subnet Phase-2) ---


def _sel_child(
    local: str, remote: str, persistent: bool, dup: int, ping: str = "none"
) -> IPsecChild:
    """A Phase-2 selector row. strongSwan/pfSense split one multi-subnet child into
    several CHILD_SAs that all carry the SAME name — only the selector pair differs."""
    return IPsecChild(
        name="con1",
        local_ts=local,
        remote_ts=remote,
        state="INSTALLED",
        dup_count=dup,
        phase2_dup_persistent=persistent,
        ping_state=ping,
    )


def test_dup_same_name_multi_selector_unchanged_emits_nothing() -> None:
    """A multi-subnet Phase-2 lists several children sharing one name, differing only
    by selector. Matching prev↔new by name alone collapses them last-wins, so a
    stuck-duplicate selector gets diffed against a non-dup sibling and re-fires
    phase2_dup_on every poll — the observed "Phase-2 duplicate" spam. Children must
    be matched by selector pair, so an unchanged snapshot yields nothing."""
    dup = _sel_child("10.10.87.0/24", "192.168.133.0/24", persistent=True, dup=2)
    plain = _sel_child(
        "10.10.88.0/24", "192.168.133.0/24", persistent=False, dup=1
    )  # sibling, listed last
    snap = _status(_tunnel(p2_up=2, p2_total=2, children=[dup, plain]))
    assert diff_ipsec(snap, _status(_tunnel(p2_up=2, p2_total=2, children=[dup, plain]))) == []


def test_dup_same_name_multi_selector_on_transition_targets_right_child() -> None:
    """The duplicate flag flipping on one selector still fires exactly one on-event,
    attributed to that selector — the sibling is untouched."""
    dup_off = _sel_child("10.10.87.0/24", "192.168.133.0/24", persistent=False, dup=1)
    plain = _sel_child("10.10.88.0/24", "192.168.133.0/24", persistent=False, dup=1)
    dup_on = _sel_child("10.10.87.0/24", "192.168.133.0/24", persistent=True, dup=2)
    prev = _status(_tunnel(p2_up=2, p2_total=2, children=[dup_off, plain]))
    new = _status(_tunnel(p2_up=2, p2_total=2, children=[dup_on, plain]))
    events = diff_ipsec(prev, new)
    assert [e.event_type for e in events] == ["phase2_dup_on"]
    assert events[0].old_value == "10.10.87.0/24 → 192.168.133.0/24"


def test_ping_same_name_multi_selector_targets_right_child() -> None:
    """Ping transitions must also key on the selector: a fail on one subnet must not
    be masked (or duplicated) by an unchanged sibling that shares the name."""
    a_ok = _sel_child("10.10.87.0/24", "192.168.133.0/24", persistent=False, dup=1, ping="ok")
    b = _sel_child("10.10.88.0/24", "192.168.133.0/24", persistent=False, dup=1, ping="ok")
    a_fail = _sel_child("10.10.87.0/24", "192.168.133.0/24", persistent=False, dup=1, ping="fail")
    prev = _status(_tunnel(p2_up=2, p2_total=2, children=[a_ok, b]))
    new = _status(_tunnel(p2_up=2, p2_total=2, children=[a_fail, b]))
    events = diff_ipsec(prev, new)
    assert [e.event_type for e in events] == ["ping_fail"]


# --- writer (record_tunnel_events) -------------------------------------------


class _FakeSession:
    """Captures the (statement, params) passed to execute — no DB."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def execute(self, stmt, params=None):  # noqa: ANN001
        self.calls.append((stmt, params))


@pytest.mark.asyncio
async def test_record_maps_events_to_rows() -> None:
    session = _FakeSession()
    ts = datetime(2026, 6, 26, 12, 0, tzinfo=UTC)
    events = [
        TunnelEvent("con1", "", "phase1_down", "established", "down"),
        TunnelEvent("con1", "c1", "ping_fail", "ok", "fail"),
    ]
    n = await record_tunnel_events(session, instance_id=7, ts=ts, events=events)
    assert n == 2
    _, rows = session.calls[0]
    assert rows[0] == {
        "instance_id": 7,
        "tunnel_id": "con1",
        "child_name": "",
        "ts": ts,
        "event_type": "phase1_down",
        "old_value": "established",
        "new_value": "down",
    }
    assert rows[1]["child_name"] == "c1"
    assert rows[1]["event_type"] == "ping_fail"


@pytest.mark.asyncio
async def test_record_empty_is_noop() -> None:
    session = _FakeSession()
    n = await record_tunnel_events(session, 1, datetime(2026, 1, 1, tzinfo=UTC), [])
    assert n == 0
    assert session.calls == []


@pytest.mark.asyncio
async def test_record_truncates_long_values() -> None:
    session = _FakeSession()
    long = "x" * 400
    events = [TunnelEvent("con1", "", "phase1_changed", long, long)]
    await record_tunnel_events(session, 1, datetime(2026, 1, 1, tzinfo=UTC), events)
    _, rows = session.calls[0]
    assert len(rows[0]["old_value"]) == 255
    assert len(rows[0]["new_value"]) == 255
