"""``insecure_tls``: lab-only escape hatch for a dashboard behind a CA the box lacks.

Off by default and per dashboard connection only (enroll + WebSocket). The enroll
exchange still verifies TLS unless the operator set the flag explicitly
(test_enroll_tls pins the default).
"""

from __future__ import annotations

import json
import ssl
from types import SimpleNamespace

import orbit_agent
import orbit_agent_linux
import pytest

LINES = [orbit_agent, orbit_agent_linux]


@pytest.mark.parametrize("agent", LINES)
def test_config_reads_insecure_tls_and_defaults_off(agent, tmp_path) -> None:
    p = tmp_path / "agent.conf"
    p.write_text(json.dumps({"dashboard_url": "wss://d.example/api/ws/agent"}))
    assert agent.Config(str(p)).insecure_tls is False
    p.write_text(json.dumps({"insecure_tls": True}))
    assert agent.Config(str(p)).insecure_tls is True


@pytest.mark.parametrize("agent", LINES)
def test_dashboard_context_verifies_unless_flag_set(agent, monkeypatch) -> None:
    monkeypatch.setattr(agent._STATE, "config", SimpleNamespace(insecure_tls=False))
    ctx = agent._dashboard_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname

    monkeypatch.setattr(agent._STATE, "config", SimpleNamespace(insecure_tls=True))
    ctx = agent._dashboard_ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE and not ctx.check_hostname

    monkeypatch.setattr(agent._STATE, "config", None)
    assert agent._dashboard_ssl_context().verify_mode == ssl.CERT_REQUIRED


@pytest.mark.parametrize("agent", LINES)
@pytest.mark.parametrize("flag,expected", [(False, True), (True, False)])
def test_enroll_verify_follows_flag(agent, monkeypatch, flag, expected) -> None:
    captured: dict[str, object] = {}

    def fake_http(url, method, headers, body, timeout, *, verify=True):
        captured["verify"] = verify
        return 200, [], b'{"agent_token": "T"}'

    monkeypatch.setattr(agent, "_http_request", fake_http)
    monkeypatch.setattr(agent, "_persist_token", lambda cfg, token: None)
    cfg = SimpleNamespace(
        agent_token="",
        enroll_code="C",
        enroll_url="https://dash.example/api/agent/enroll",
        dashboard_url="wss://dash.example/ws/agent",
        insecure_tls=flag,
    )
    assert agent._enroll(cfg) is True
    assert captured["verify"] is expected
