"""Tests for the agent's command dispatch (execute_command).

Pure-logic: subprocess calls are stubbed via _run. Covers the dispatch
contract that the (future) self-update action will extend.
"""

from __future__ import annotations

import opnsense_agent as agent
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


def test_firmware_check_pfsense_uses_pfsense_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        captured["cmd"] = cmd
        return "Your system is up to date"

    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_run", fake_run)
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "2.8.1-RELEASE")
    result = agent.execute_command("firmware.check", {})
    assert captured["cmd"] == ["/usr/local/sbin/pfSense-upgrade", "-c"]
    assert result["product_version"] == "2.8.1-RELEASE"


def test_firmware_check_opnsense_uses_opnsense_update(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_run(cmd: list[str], timeout: int = 5) -> str:
        captured["cmd"] = cmd
        return "up to date"

    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_run", fake_run)
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "25.7.11_9")
    result = agent.execute_command("firmware.check", {})
    assert captured["cmd"] == ["/usr/local/sbin/opnsense-update", "-c"]
    assert result["product_version"] == "25.7.11_9"


def test_ipsec_restart_fire_and_forget_onerestart(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_popen(cmd: list[str], **kwargs: object) -> object:
        captured["cmd"] = cmd
        return object()

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    result = agent.execute_command("ipsec.restart", {})
    # `onerestart` (not `restart`) — pfSense doesn't set strongswan_enable in rc.conf.
    # Fire-and-forget so the slow pfSense config regen can't race the command timeout.
    assert captured["cmd"] == ["service", "strongswan", "onerestart"]
    assert result["success"] is True


def test_config_backup_missing_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent.os.path, "exists", lambda p: False)
    result = agent.execute_command("config.backup", {})
    assert result["success"] is False
