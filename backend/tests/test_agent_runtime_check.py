"""agent.collect check — WARN >= 10s, OK below, absent on the direct-poll path."""

from __future__ import annotations

from app.agent_hub.converters import status_from_agent
from app.checks.agent_runtime import agent_collect_check
from app.xsense.schemas import SystemStatus


def test_none_on_direct_poll() -> None:
    # No collect_ms (direct-poll instance) → no agent.collect check at all.
    assert agent_collect_check(SystemStatus()) is None


def test_ok_below_threshold() -> None:
    s = SystemStatus(collect_ms=2500.0, section_ms={"certificates": 2000.0, "ipsec": 500.0})
    c = agent_collect_check(s)
    assert c is not None
    assert c.key == "agent.collect"
    assert c.state == 0  # OK
    names = [m.name for m in c.metrics]
    assert names == ["collect_ms"]  # only the whole-cycle total as perfdata


def test_warn_at_threshold_names_slowest_section() -> None:
    s = SystemStatus(collect_ms=12000.0, section_ms={"certificates": 9000.0, "ipsec": 2500.0})
    c = agent_collect_check(s)
    assert c is not None
    assert c.state == 1  # WARN
    assert "certificates" in c.summary  # slowest section surfaced
    total = next(m for m in c.metrics if m.name == "collect_ms")
    assert total.warn == 10000.0
    assert total.unit == "ms"


def test_status_from_agent_parses_collect_timing() -> None:
    s = status_from_agent({"collect_ms": 1234.5, "section_ms": {"certificates": 1000.0}})
    assert s.collect_ms == 1234.5
    assert s.section_ms == {"certificates": 1000.0}


def test_status_from_agent_no_timing_is_none() -> None:
    s = status_from_agent({})
    assert s.collect_ms is None
    assert s.section_ms == {}
