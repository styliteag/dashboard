"""Tests for agent lifecycle: uninstall teardown script + enrollment (§16 chunk C).

Pure-logic: the uninstall script is built (not run), and enrollment's HTTP call is
stubbed. Covers teardown ordering, enroll-URL derivation, the enroll exchange, and
token persistence (the single-use-code correctness hazard).
"""

from __future__ import annotations

import json

import orbit_agent as agent
import pytest


# --- uninstall teardown script ----------------------------------------------


def test_uninstall_kills_supervisor_before_agent() -> None:
    script = agent._build_uninstall_script(
        "/usr/local/orbit-agent", "/usr/local/etc/rc.d/orbit_agent", "/tmp/d.php", True
    )
    sup = script.index("pkill -f run-agent.sh")
    ag = script.index("pkill -f orbit_agent.py")
    # The supervisor MUST die first, else it respawns the agent we just killed.
    assert sup < ag


def test_uninstall_removes_footprint() -> None:
    script = agent._build_uninstall_script(
        "/usr/local/orbit-agent", "/usr/local/etc/rc.d/orbit_agent", "/tmp/d.php", True
    )
    assert "rm -rf /usr/local/orbit-agent" in script
    assert "rm -f /usr/local/etc/rc.d/orbit_agent" in script
    assert "sysrc -x orbit_agent_enable" in script  # don't revive on reboot
    assert "/tmp/d.php" in script  # deprovision invoked


def test_uninstall_skips_deprovision_when_disabled() -> None:
    script = agent._build_uninstall_script(
        "/usr/local/orbit-agent", "/usr/local/etc/rc.d/orbit_agent", "/tmp/d.php", False
    )
    assert "php /tmp/d.php" not in script
    assert "rm -rf /usr/local/orbit-agent" in script  # still tears the agent down


# --- enrollment URL derivation ----------------------------------------------


def test_derive_enroll_url_from_wss() -> None:
    url = agent._derive_enroll_url("wss://dash.example.com/api/ws/agent")
    assert url == "https://dash.example.com/api/agent/enroll"


def test_derive_enroll_url_from_ws() -> None:
    url = agent._derive_enroll_url("ws://10.20.0.24:8000/api/ws/agent")
    assert url == "http://10.20.0.24:8000/api/agent/enroll"


def test_derive_enroll_url_unknown_path_falls_back() -> None:
    url = agent._derive_enroll_url("wss://dash.example.com/socket")
    assert url == "https://dash.example.com/api/agent/enroll"


def test_derive_enroll_url_empty_when_no_host() -> None:
    assert agent._derive_enroll_url("not-a-url") == ""


# --- enrollment exchange + persistence --------------------------------------


def _cfg(tmp_path, **over) -> agent.Config:
    cfg = agent.Config(path=str(tmp_path / "agent.conf"))
    cfg.dashboard_url = "ws://10.20.0.24:8000/api/ws/agent"
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def test_enroll_skips_when_token_present(tmp_path, monkeypatch) -> None:
    called = {"n": 0}
    monkeypatch.setattr(agent, "_http_request", lambda *a, **k: called.__setitem__("n", 1))
    cfg = _cfg(tmp_path, agent_token="EXISTING", enroll_code="CODE")
    assert agent._enroll(cfg) is False
    assert called["n"] == 0  # never hits the network when a token already exists


def test_enroll_skips_when_no_code(tmp_path) -> None:
    assert agent._enroll(_cfg(tmp_path)) is False


def test_enroll_success_sets_and_persists_token(tmp_path, monkeypatch) -> None:
    body = json.dumps({"agent_token": "NEWTOKEN", "instance_id": 7}).encode()
    captured: dict = {}

    def fake_req(url, method, headers, payload, timeout):
        captured["url"] = url
        captured["payload"] = payload
        return 200, [], body

    monkeypatch.setattr(agent, "_http_request", fake_req)
    cfg = _cfg(tmp_path, enroll_code="THECODE")
    assert agent._enroll(cfg) is True
    assert cfg.agent_token == "NEWTOKEN"
    assert captured["url"] == "http://10.20.0.24:8000/api/agent/enroll"
    assert json.loads(captured["payload"]) == {"code": "THECODE"}
    # Persisted so a restart reuses the token, not the now-spent code.
    saved = json.loads((tmp_path / "agent.conf").read_text())
    assert saved["agent_token"] == "NEWTOKEN"
    assert "enroll_code" not in saved


def test_enroll_failure_on_non_200(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(agent, "_http_request", lambda *a, **k: (401, [], b"nope"))
    cfg = _cfg(tmp_path, enroll_code="BAD")
    assert agent._enroll(cfg) is False
    assert cfg.agent_token == ""


def test_persist_token_drops_spent_code(tmp_path) -> None:
    conf = tmp_path / "agent.conf"
    conf.write_text(json.dumps({"dashboard_url": "ws://x/api/ws/agent", "enroll_code": "C"}))
    cfg = agent.Config(path=str(conf))
    agent._persist_token(cfg, "TOK")
    saved = json.loads(conf.read_text())
    assert saved["agent_token"] == "TOK"
    assert "enroll_code" not in saved
    assert saved["dashboard_url"] == "ws://x/api/ws/agent"  # other keys preserved
