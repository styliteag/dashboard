"""Enrollment must exchange the one-time code over a TLS-verified channel.

The bootstrap step trades the single-use enroll code (a secret) for the long-lived
agent token; sending it over an unverified TLS connection lets an on-path attacker
harvest the code / forge the token. The shared _http_request helper skips
verification only for the loopback self-signed API.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import orbit_agent as agent


def test_http_request_verifies_tls_by_default() -> None:
    # Guard: nobody may flip the default back to unverified.
    assert inspect.signature(agent._http_request).parameters["verify"].default is True


def test_enroll_requires_verified_tls(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_http(url, method, headers, body, timeout, *, verify=True):
        captured["url"] = url
        captured["verify"] = verify
        return 200, [], b'{"agent_token": "TKN-123"}'

    monkeypatch.setattr(agent, "_http_request", fake_http)
    monkeypatch.setattr(agent, "_persist_token", lambda cfg, token: None)

    cfg = SimpleNamespace(
        agent_token="",
        enroll_code="ONE-TIME-CODE",
        enroll_url="https://dash.example/api/agent/enroll",
        dashboard_url="wss://dash.example/ws/agent",
    )
    assert agent._enroll(cfg) is True
    assert cfg.agent_token == "TKN-123"
    assert captured["verify"] is True  # remote dashboard → MUST verify
    assert captured["url"] == "https://dash.example/api/agent/enroll"
