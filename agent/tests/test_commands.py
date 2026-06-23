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


def test_config_backup_missing_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent.os.path, "exists", lambda p: False)
    result = agent.execute_command("config.backup", {})
    assert result["success"] is False
