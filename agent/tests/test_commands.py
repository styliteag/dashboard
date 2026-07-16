"""Tests for the agent's command dispatch (execute_command).

Pure-logic: subprocess calls are stubbed via _run. Covers the dispatch
contract that the (future) self-update action will extend.
"""

from __future__ import annotations

import orbit_agent as agent
import pytest


def test_ping_returns_pong() -> None:
    result = agent.execute_command("ping", {})
    assert result["success"] is True
    assert result["output"] == "pong"
    assert result["agent_version"] == agent.__version__


def test_unknown_action_is_reported() -> None:
    result = agent.execute_command("does.not.exist", {})
    assert result["success"] is False
    assert "unknown action" in result["output"]
    assert "does.not.exist" in result["output"]


def test_ipsec_connect_success_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "initiate completed successfully")
    result = agent.execute_command("ipsec.connect", {"tunnel_id": "7"})
    assert result["success"] is True


def test_ipsec_connect_failure_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "establishing CHILD_SA failed")
    result = agent.execute_command("ipsec.connect", {"tunnel_id": "7"})
    assert result["success"] is False


# Verbatim `swanctl --list-conns --raw`: connection 34595782… with one child
# 0d68b529… (same shape as the real OPNsense boxes).
_CONNS_RAW = (
    "list-conn event {34595782-ae4a-41b8-8722-2d52eb487475 "
    "{local_addrs=[10.21.7.100] remote_addrs=[10.21.7.101] version=IKEv2 "
    "children {0d68b529-eeca-4db4-9e17-5d6a008f9164 "
    "{mode=TUNNEL local-ts=[10.1.1.0/24] remote-ts=[10.2.2.0/24]}}}}\n"
    "list-conns reply {}"
)


def test_connection_child_names_parses_children(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_run", lambda *a, **k: _CONNS_RAW)
    assert agent._connection_child_names("34595782-ae4a-41b8-8722-2d52eb487475") == [
        "0d68b529-eeca-4db4-9e17-5d6a008f9164"
    ]
    assert agent._connection_child_names("no-such-conn") == []
    assert agent._connection_child_names("") == []


def test_ipsec_connect_also_initiates_children(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], *a: object, **k: object) -> str:
        calls.append(cmd)
        if "--list-conns" in cmd:
            return _CONNS_RAW
        return "initiate completed successfully"

    monkeypatch.setattr(agent, "_run", fake_run)
    result = agent.execute_command(
        "ipsec.connect", {"tunnel_id": "34595782-ae4a-41b8-8722-2d52eb487475"}
    )
    assert result["success"] is True
    # Phase 1 first, then the configured Phase-2 child.
    assert ["swanctl", "--initiate", "--ike", "34595782-ae4a-41b8-8722-2d52eb487475"] in calls
    assert [
        "swanctl",
        "--initiate",
        "--child",
        "0d68b529-eeca-4db4-9e17-5d6a008f9164",
    ] in calls


def test_ipsec_diagnose_gathers_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent.os.path, "exists", lambda p: p == "/var/log/ipsec/latest.log")

    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        if cmd[:2] == ["swanctl", "--list-conns"] and "--raw" in cmd:
            return (
                "list-conn event {tun-x {local_addrs=[10.0.0.1] remote_addrs=[1.2.3.4] "
                "children {c {mode=TUNNEL local-ts=[10.1.0.0/24] remote-ts=[10.2.0.0/24]}}}}"
            )
        if cmd[:2] == ["swanctl", "--list-conns"]:
            return "tun-x: IKEv2\n  remote: 1.2.3.4"
        if cmd[:2] == ["swanctl", "--list-sas"]:
            return "tun-x: #1 ESTABLISHED"
        if cmd[0] == "tail":
            return "noise\n<tun-x|3> AUTHENTICATION_FAILED, peer rejected\nmore noise"
        if cmd[0] == "ping":
            return "2 packets transmitted, 2 packets received, 0.0% packet loss"
        return ""

    monkeypatch.setattr(agent, "_run", fake_run)
    res = agent.execute_command("ipsec.diagnose", {"tunnel_id": "tun-x"})

    assert res["success"] is True
    by_title = {s["title"]: s["content"] for s in res["sections"]}
    assert any("config" in t.lower() for t in by_title)
    # The conn-tagged failure line is surfaced in the log section.
    log = next(c for t, c in by_title.items() if "log" in t.lower())
    assert "AUTHENTICATION_FAILED" in log
    # A concrete remote → ping ran.
    ping = next(c for t, c in by_title.items() if "reachability" in t.lower())
    assert "2 packets received" in ping


def test_firmware_check_pfsense_uses_pfsense_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        captured["cmd"] = cmd
        return "Your system is up to date"

    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_run", fake_run)
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "2.8.1-RELEASE")
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "26.03")
    monkeypatch.setattr(agent, "_list_pfsense_branches", lambda: ["26.03", "dev"])
    result = agent.execute_command("firmware.check", {})
    assert captured["cmd"] == ["/usr/local/sbin/pfSense-upgrade", "-c"]
    assert result["product_version"] == "2.8.1-RELEASE"
    assert result["branch"] == "26.03"
    assert "dev" in (result.get("known_branches") or [])


def test_firmware_check_opnsense_uses_opnsense_update(monkeypatch: pytest.MonkeyPatch) -> None:
    cmds: list[list[str]] = []

    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        cmds.append(cmd)
        if cmd[:2] == ["/usr/local/sbin/opnsense-update", "-c"]:
            return "up to date"
        if cmd[:3] == ["pkg", "query", "%v"]:
            return "26.1.9"
        if cmd[:3] == ["pkg", "rquery", "%v"]:
            return "26.1.10"  # a newer core package is available
        if cmd == ["opnsense-version"]:
            return '{"product_series": "26.1"}'
        return ""  # pkg update -q

    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_run", fake_run)
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.1.9")
    result = agent.execute_command("firmware.check", {})
    assert ["/usr/local/sbin/opnsense-update", "-c"] in cmds
    assert result["product_version"] == "26.1.9"
    assert result["product_latest"] == "26.1.10"  # pkg point release surfaced
    assert result["upgrade_available"] is True
    assert result.get("branch") == "26.1"
    assert result.get("known_branches") == []


def _capture_popen(monkeypatch: pytest.MonkeyPatch) -> dict:
    captured: dict = {}

    def fake_popen(cmd: list[str], **kwargs: object) -> object:
        captured["cmd"] = cmd
        return object()

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    return captured


def test_ipsec_restart_pfsense_uses_ipsec_configure(monkeypatch: pytest.MonkeyPatch) -> None:
    # `service strongswan restart` on pfSense restarts charon with an EMPTY
    # conf.d → drops every tunnel. Must regenerate+reload via ipsec_configure().
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    captured = _capture_popen(monkeypatch)
    result = agent.execute_command("ipsec.restart", {})
    assert captured["cmd"][0] == "php"
    assert "ipsec_configure();" in captured["cmd"][2]
    assert result["success"] is True


def test_ipsec_restart_opnsense_uses_configctl(monkeypatch: pytest.MonkeyPatch) -> None:
    # OPNsense conf.d is empty too — `service strongswan restart` would drop every
    # tunnel. configctl ipsec reload regenerates+reloads non-destructively.
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    captured = _capture_popen(monkeypatch)
    result = agent.execute_command("ipsec.restart", {})
    assert captured["cmd"] == ["configctl", "ipsec", "reload"]
    assert result["success"] is True


def test_config_backup_missing_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent.os.path, "exists", lambda p: False)
    result = agent.execute_command("config.backup", {})
    assert result["success"] is False


def test_firmware_upgrade_pfsense_switches_train_then_starts_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression (pre-3.1.3): pfSense series upgrades were text-only — the agent
    refused firmware.upgrade on pfsense and the dashboard told the operator to
    switch the branch in the vendor GUI. The agent now switches the train
    on-box (target from the box's own repo descriptors, never the dashboard)
    and starts the regular updater."""
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "2_7_2")
    monkeypatch.setattr(agent, "_pfsense_newer_branch", lambda b: ("2_8_1", "2.8.1"))
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "2.7.2-RELEASE")
    monkeypatch.setattr(agent, "_zfs_boot_snapshot", lambda v: "orbit-pre-2.7.2-RELEASE")
    switched: list[str] = []

    def fake_switch(train: str) -> str:
        switched.append(train)
        return ""

    monkeypatch.setattr(agent, "_pfsense_switch_train", fake_switch)
    captured = _capture_popen(monkeypatch)
    result = agent.execute_command("firmware.upgrade", {})
    assert switched == ["2_8_1"]
    assert captured["cmd"] == ["/usr/local/sbin/pfSense-upgrade", "-y"]
    assert result["success"] is True
    assert "2.8.1" in result["output"]
    assert "orbit-pre-2.7.2-RELEASE" in result["output"]


def test_firmware_upgrade_pfsense_requires_offered_train(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "2_8_1")
    monkeypatch.setattr(agent, "_pfsense_newer_branch", lambda b: ("", ""))
    captured = _capture_popen(monkeypatch)
    result = agent.execute_command("firmware.upgrade", {})
    assert result["success"] is False
    assert "cmd" not in captured


def test_firmware_upgrade_pfsense_aborts_when_branch_switch_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A half-switched box must never start the updater — the operator gets the
    # switch error and the box stays on its pinned train.
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "2_7_2")
    monkeypatch.setattr(agent, "_pfsense_newer_branch", lambda b: ("2_8_1", "2.8.1"))
    monkeypatch.setattr(agent, "_pfsense_switch_train", lambda t: "php exploded")
    captured = _capture_popen(monkeypatch)
    result = agent.execute_command("firmware.upgrade", {})
    assert result["success"] is False
    assert "php exploded" in result["output"]
    assert "cmd" not in captured


def test_firmware_upgrade_refused_on_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    captured = _capture_popen(monkeypatch)
    result = agent.execute_command("firmware.upgrade", {})
    assert result["success"] is False
    assert "cmd" not in captured


def test_pfsense_switch_train_rejects_bad_train_id(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> str:
        raise AssertionError("php must not run for an invalid train id")

    monkeypatch.setattr(agent, "_run", boom)
    assert "invalid train id" in agent._pfsense_switch_train("2_8_1; rm -rf /")
    assert "invalid train id" in agent._pfsense_switch_train("")


def test_pfsense_switch_train_parses_ok_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    # repoc noise before the marker is fine — only the last line decides.
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "some repoc noise\nok\n")
    assert agent._pfsense_switch_train("2_8_1") == ""
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "train not offered by this box: 9_9")
    assert "not offered" in agent._pfsense_switch_train("9_9")
    # php missing / silent death (empty _run) must not read as success.
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "")
    assert agent._pfsense_switch_train("2_8_1") != ""


def test_firmware_check_pfsense_reports_series_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The manual firmware.check must fold the newer-train verdict in exactly
    like collect_firmware — before 3.1.3 it skipped _pfsense_newer_branch, so
    a manual "Check now" overwrote the cached verdict WITHOUT the series offer
    and the dashboard's upgrade button vanished until the next ~12h check."""
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "Your system is up to date")
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "2.7.2-RELEASE")
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "2_7_2")
    monkeypatch.setattr(agent, "_list_pfsense_branches", lambda: ["2_7_2", "2_8_1"])
    monkeypatch.setattr(agent, "_pfsense_newer_branch", lambda b: ("2_8_1", "2.8.1"))
    result = agent.execute_command("firmware.check", {})
    assert result["upgrade_available"] is True
    assert result["product_latest"] == "2.8.1"
    assert result["upgrade_major_version"] == "2.8.1"
    assert "newer release train available" in result["output"]
