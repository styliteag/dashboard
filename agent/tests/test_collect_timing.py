"""Whole-cycle + per-section collection timing added to collect_all."""

from __future__ import annotations

import orbit_agent as agent

_SECTIONS = {
    "system": {"hostname": "fw"},
    "uptime": "up",
    "loadavg": {},
    "cpu": {},
    "memory": {},
    "disks": [],
    "pf": {},
    "ntp": {},
    "interfaces": [],
    "gateways": [],
    "ipsec": {},
    "connectivity": [],
    "firmware": {},
    "firewall_log": [],
    "config": {},
    "services": [],
    "certificates": [],
    "logfiles": {},
}

_STUB_FN = {
    "system": "collect_system_info",
    "uptime": "collect_uptime",
    "loadavg": "collect_loadavg",
    "cpu": "collect_cpu",
    "memory": "collect_memory",
    "disks": "collect_disk",
    "pf": "collect_pf",
    "ntp": "collect_ntp",
    "interfaces": "collect_interfaces",
    "gateways": "collect_gateways",
    "ipsec": "collect_ipsec",
    "connectivity": "collect_connectivity",
    "firmware": "collect_firmware",
    "firewall_log": "collect_firewall_log",
    "config": "collect_config",
    "services": "collect_services",
    "certificates": "collect_certificates",
    "logfiles": "collect_logfiles",
}


def test_timed_records_ms_and_returns_result() -> None:
    timings: dict = {}
    result = agent._timed(timings, "x", lambda: 42)
    assert result == 42
    assert isinstance(timings["x"], float)
    assert timings["x"] >= 0


def test_timed_records_ms_even_when_fn_raises() -> None:
    timings: dict = {}

    def boom():
        raise ValueError("nope")

    try:
        agent._timed(timings, "boom", boom)
    except ValueError:
        pass
    else:
        raise AssertionError("_timed must re-raise")
    assert "boom" in timings  # finally recorded despite the error


def test_collect_all_adds_collect_ms_and_section_ms(monkeypatch) -> None:
    # Stub every collector so collect_all runs no real OS commands.
    for key, fn_name in _STUB_FN.items():
        monkeypatch.setattr(agent, fn_name, lambda *a, _v=_SECTIONS[key]: _v)
    snap = agent.collect_all()
    assert isinstance(snap["collect_ms"], float)
    assert snap["collect_ms"] >= 0
    assert set(snap["section_ms"]) == set(_SECTIONS)
    assert all(isinstance(v, float) for v in snap["section_ms"].values())
    assert snap["system"] == {"hostname": "fw"}
