"""Tests for the agent's Phase-2 child detail + ping-monitor probing."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import orbit_agent as agent

_SAS = (
    "conn-a {uniqueid=1 state=ESTABLISHED remote-host=1.1.1.1 local-host=9.9.9.9 established=10 "
    "child-sas {x-1 {name=x uniqueid=1 state=INSTALLED bytes-in=5 bytes-out=7 "
    "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}"
)
_CONNS = (
    "c1 {local_addrs=[9.9.9.9] remote_addrs=[1.1.1.1] version=IKEv2 "
    "children {y {mode=TUNNEL local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}"
)


# --- per-child parsing -------------------------------------------------------


def test_parse_sas_keeps_child_detail() -> None:
    child = agent._parse_swanctl_sas(_SAS)[0]["children"][0]
    assert child["name"] == "x"  # bare name, not the "-1" section key
    assert child["local_ts"] == "10.1.1.0/24"
    assert child["remote_ts"] == "10.2.2.0/24"
    assert child["state"] == "INSTALLED"
    assert (child["bytes_in"], child["bytes_out"]) == (5, 7)


def test_parse_sas_strips_pfsense_ts_proto_port_suffix() -> None:
    # pfSense's strongSwan appends a "|proto/port" part to traffic selectors
    # ("10.3.3.0/24|/0"); OPNsense omits it. The dashboard wants just the subnet.
    raw = (
        "con1 {uniqueid=1 state=ESTABLISHED remote-host=1.1.1.1 local-host=9.9.9.9 "
        "child-sas {con1-3 {name=con1 state=INSTALLED bytes-in=1 bytes-out=2 "
        "local-ts=[10.3.3.0/24|/0] remote-ts=[10.1.1.0/24|/0]}}}"
    )
    child = agent._parse_swanctl_sas(raw)[0]["children"][0]
    assert child["local_ts"] == "10.3.3.0/24"
    assert child["remote_ts"] == "10.1.1.0/24"


def test_parse_conns_strips_pfsense_ts_proto_port_suffix() -> None:
    raw = (
        "con1 {local_addrs=[9.9.9.9] remote_addrs=[1.1.1.1] version=IKEv2 "
        "children {con1 {mode=TUNNEL local-ts=[10.3.3.0/24|/0] remote-ts=[10.1.1.0/24|/0]}}}"
    )
    child = agent._parse_swanctl_conns(raw)[0]["children"][0]
    assert child["local_ts"] == "10.3.3.0/24"
    assert child["remote_ts"] == "10.1.1.0/24"


def test_clean_ts_variants() -> None:
    assert agent._clean_ts("10.3.3.0/24|/0") == "10.3.3.0/24"  # pfSense proto/port
    assert agent._clean_ts("10.1.1.0/24") == "10.1.1.0/24"  # OPNsense clean
    assert agent._clean_ts("10.1.1.0/24[tcp/80]") == "10.1.1.0/24"  # classic bracket form
    assert agent._clean_ts("") == ""


def test_parse_sas_dedupes_rekey_child_dups() -> None:
    # Two child SAs for the SAME selector pair (make-before-break rekey) collapse
    # to one Phase 2 — fixes the "4/2" double-count. Keeps the higher-traffic one.
    raw = (
        "conn-a {uniqueid=1 state=ESTABLISHED remote-host=1.1.1.1 local-host=9.9.9.9 "
        "child-sas {a-1 {name=a state=INSTALLED bytes-in=10 bytes-out=20 "
        "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]} "
        "a-2 {name=a state=INSTALLED bytes-in=1 bytes-out=2 "
        "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}"
    )
    s = agent._parse_swanctl_sas(raw)[0]
    assert s["phase2_up"] == 1
    assert s["phase2_total"] == 1
    assert len(s["children"]) == 1
    assert (s["bytes_in"], s["bytes_out"]) == (10, 20)  # higher-traffic SA wins


def test_parse_sas_keeps_distinct_selectors() -> None:
    # Two DIFFERENT selector pairs = two real Phase 2 → both kept (2/2).
    raw = (
        "conn-a {uniqueid=1 state=ESTABLISHED remote-host=1.1.1.1 local-host=9.9.9.9 "
        "child-sas {a {name=a state=INSTALLED local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]} "
        "b {name=b state=INSTALLED local-ts=[10.99.1.0/24] remote-ts=[10.99.2.0/24]}}}"
    )
    s = agent._parse_swanctl_sas(raw)[0]
    assert s["phase2_up"] == 2
    assert s["phase2_total"] == 2
    assert len(s["children"]) == 2


def test_parse_sas_exposes_spis() -> None:
    # SPIs for cross-instance pairing: child spi-in/out + IKE initiator/responder.
    raw = (
        "conn-a {uniqueid=1 state=ESTABLISHED remote-host=1.1.1.1 local-host=9.9.9.9 "
        "initiator-spi=aaaa1111 responder-spi=bbbb2222 "
        "child-sas {a {name=a state=INSTALLED spi-in=c4b835fe spi-out=ce1dea08 "
        "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}"
    )
    s = agent._parse_swanctl_sas(raw)[0]
    assert s["ike_init_spi"] == "aaaa1111"
    assert s["ike_resp_spi"] == "bbbb2222"
    assert s["children"][0]["spi_in"] == "c4b835fe"
    assert s["children"][0]["spi_out"] == "ce1dea08"


def test_tunnel_carries_spis() -> None:
    sa = agent._parse_swanctl_sas(
        "conn-a {uniqueid=1 state=ESTABLISHED remote-host=1.1.1.1 local-host=9.9.9.9 "
        "initiator-spi=aaaa1111 responder-spi=bbbb2222 "
        "child-sas {a {name=a state=INSTALLED spi-in=11 spi-out=22 "
        "local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}"
    )[0]
    t = agent._tunnel("c", None, sa, {})
    assert t["ike_init_spi"] == "aaaa1111"
    assert t["children"][0]["spi_out"] == "22"
    # down tunnel: no SPIs
    down = agent._tunnel("c", {"phase2_total": 1, "children": []}, None, {})
    assert down["ike_init_spi"] == ""


def test_parse_conns_keeps_child_selectors() -> None:
    child = agent._parse_swanctl_conns(_CONNS)[0]["children"][0]
    assert child["name"] == "y"
    assert child["local_ts"] == "10.1.1.0/24"
    assert child["remote_ts"] == "10.2.2.0/24"


def test_merge_children_overlays_live_state_by_selector() -> None:
    # name drifted (y vs x) but the selector pair matches → live state overlaid.
    conn_children = [{"name": "y", "local_ts": "10.1.1.0/24", "remote_ts": "10.2.2.0/24"}]
    sa_children = [
        {"name": "x", "local_ts": "10.1.1.0/24", "remote_ts": "10.2.2.0/24",
         "state": "INSTALLED", "bytes_in": 1, "bytes_out": 2}
    ]
    merged = agent._merge_children(conn_children, sa_children)
    assert len(merged) == 1
    assert merged[0]["name"] == "y"  # configured name preferred
    assert merged[0]["state"] == "INSTALLED"


def test_merge_children_surfaces_configured_down() -> None:
    merged = agent._merge_children([{"name": "y", "local_ts": "a", "remote_ts": "b"}], [])
    assert merged[0]["state"] == ""  # configured but no live SA → down


def test_tunnel_includes_children() -> None:
    sa = agent._parse_swanctl_sas(_SAS)[0]
    conn = agent._parse_swanctl_conns(_CONNS)[0]
    t = agent._tunnel("c1", conn, sa, {})
    assert t["children"][0]["remote_ts"] == "10.2.2.0/24"
    assert t["children"][0]["state"] == "INSTALLED"


# --- suggested source --------------------------------------------------------


def test_suggest_source_picks_box_ip_in_selector() -> None:
    assert agent._suggest_source("10.1.1.0/24", ["10.20.1.1", "10.1.1.5"]) == "10.1.1.5"


def test_suggest_source_empty_when_no_match() -> None:
    assert agent._suggest_source("10.1.1.0/24", ["10.20.1.1"]) == ""
    assert agent._suggest_source("", ["10.1.1.5"]) == ""


# --- ping classification -----------------------------------------------------


def _fake_run(stdout: str = "", stderr: str = ""):
    def _run(*a, **k):
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)

    return _run


def test_ping_once_ok(monkeypatch) -> None:
    monkeypatch.setattr(
        agent.subprocess,
        "run",
        _fake_run(
            "3 packets transmitted, 3 packets received, 0.0% packet loss\n"
            "round-trip min/avg/max/stddev = 0.1/0.5/0.9/0.0 ms"
        ),
    )
    res = agent._ping_once("10.1.1.5", "10.2.2.1", 3)
    assert res["ping_state"] == "ok"
    assert res["ping_loss_pct"] == 0.0
    assert res["ping_rtt_ms"] == 0.5


def test_ping_once_fail_on_total_loss(monkeypatch) -> None:
    monkeypatch.setattr(
        agent.subprocess,
        "run",
        _fake_run("3 packets transmitted, 0 packets received, 100.0% packet loss"),
    )
    assert agent._ping_once("10.1.1.5", "10.2.2.1", 3)["ping_state"] == "fail"


def test_ping_once_error_on_bad_source(monkeypatch) -> None:
    # No loss summary (bind failed) → misconfiguration, not an outage.
    monkeypatch.setattr(
        agent.subprocess,
        "run",
        _fake_run(stderr="ping: bind: Can't assign requested address"),
    )
    assert agent._ping_once("10.9.9.9", "10.2.2.1", 3)["ping_state"] == "error"


def test_ping_once_error_without_dest() -> None:
    assert agent._ping_once("10.1.1.5", "", 3)["ping_state"] == "error"


# --- monitor matching + run --------------------------------------------------


def test_match_monitor_by_name_and_selector() -> None:
    tunnel = {"id": "con1"}
    child = {"name": "x", "local_ts": "10.1.1.0/24", "remote_ts": "10.2.2.0/24"}
    by_name = [{"tunnel_id": "con1", "child_name": "x", "enabled": True}]
    by_sel = [
        {"tunnel_id": "con1", "child_name": "drifted", "enabled": True,
         "local_ts": "10.1.1.0/24", "remote_ts": "10.2.2.0/24"}
    ]
    whole = [{"tunnel_id": "con1", "child_name": "", "enabled": True}]
    assert agent._match_monitor(tunnel, child, by_name) is by_name[0]
    assert agent._match_monitor(tunnel, child, by_sel) is by_sel[0]
    assert agent._match_monitor(tunnel, child, whole) is whole[0]


def test_match_monitor_skips_disabled_and_other_tunnel() -> None:
    tunnel = {"id": "con1"}
    child = {"name": "x"}
    assert agent._match_monitor(tunnel, child, [{"tunnel_id": "con1", "child_name": "x", "enabled": False}]) is None
    assert agent._match_monitor(tunnel, child, [{"tunnel_id": "con2", "child_name": "x", "enabled": True}]) is None


def test_run_ping_checks_annotates_child(monkeypatch) -> None:
    monkeypatch.setattr(
        agent, "_ping_once",
        lambda src, dst, cnt: {"ping_state": "ok", "ping_loss_pct": 0.0, "ping_rtt_ms": 1.0},
    )
    child = {"name": "x", "local_ts": "10.1.1.0/24", "remote_ts": "10.2.2.0/24", "ping_state": "none"}
    tunnels = [{"id": "con1", "children": [child]}]
    monitors = [
        {"tunnel_id": "con1", "child_name": "x", "enabled": True,
         "source": "10.1.1.5", "destination": "10.2.2.1", "ping_count": 3}
    ]
    agent.run_ping_checks(tunnels, monitors, "2026-06-26T00:00:00+00:00")
    assert child["ping_state"] == "ok"
    assert child["ping_ts"] == "2026-06-26T00:00:00+00:00"


def test_run_ping_checks_noop_without_monitors() -> None:
    child = {"name": "x", "ping_state": "none"}
    agent.run_ping_checks([{"id": "con1", "children": [child]}], [], "now")
    assert child["ping_state"] == "none"  # untouched


@pytest.mark.parametrize("monitors", [[], None])
def test_run_ping_checks_handles_empty(monitors) -> None:
    # Should not raise on empty / falsy monitor lists.
    agent.run_ping_checks([{"id": "c", "children": []}], monitors or [], "now")


# --- one-off test command (config dialog "Test now") -------------------------


def test_ping_test_command_ok(monkeypatch) -> None:
    monkeypatch.setattr(
        agent, "_ping_once",
        lambda s, d, c: {"ping_state": "ok", "ping_rtt_ms": 1.2, "ping_loss_pct": 0.0},
    )
    r = agent.execute_command(
        "ipsec.ping_test", {"source": "10.1.1.5", "destination": "10.2.2.1", "ping_count": 3}
    )
    assert r["success"] is True
    assert r["ping_state"] == "ok"
    assert "reply" in r["output"]


def test_ping_test_command_fail(monkeypatch) -> None:
    monkeypatch.setattr(
        agent, "_ping_once",
        lambda s, d, c: {"ping_state": "fail", "ping_rtt_ms": None, "ping_loss_pct": 100.0},
    )
    r = agent.execute_command("ipsec.ping_test", {"destination": "10.2.2.1"})
    assert r["success"] is False
    assert r["ping_state"] == "fail"


def test_ping_test_command_error(monkeypatch) -> None:
    monkeypatch.setattr(
        agent, "_ping_once",
        lambda s, d, c: {"ping_state": "error", "ping_rtt_ms": None, "ping_loss_pct": None},
    )
    r = agent.execute_command(
        "ipsec.ping_test", {"source": "9.9.9.9", "destination": "10.2.2.1"}
    )
    assert r["success"] is False
    assert r["ping_state"] == "error"
