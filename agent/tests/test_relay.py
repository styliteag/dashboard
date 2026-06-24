"""Tests for the local API relay (http.relay action).

The relay tunnels a dashboard HTTP request to the box's own OPNsense REST API,
injecting Basic auth locally so the dashboard never holds firewall credentials.
The actual HTTPS call (_http_request) and provisioning (_run PHP) are stubbed —
these cover the pure request/response mapping, auth injection, header filtering,
credential precedence, and dispatch.
"""

from __future__ import annotations

import base64
import json

import opnsense_agent as agent
import pytest


def _cfg(**over: object) -> agent.Config:
    cfg = agent.Config(path="/nonexistent-relay-test")
    cfg.opnsense_api_url = "https://127.0.0.1:4444"
    cfg.relay_provision = False  # tests opt in explicitly
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def _decode_basic(header: str) -> tuple[str, str]:
    raw = base64.b64decode(header.split(" ", 1)[1]).decode()
    key, _, secret = raw.partition(":")
    return key, secret


# --- credential resolution ---------------------------------------------------


def test_no_config_yields_transport_failure() -> None:
    result = agent._relay_http({"method": "GET", "path": "api/x"}, None)
    assert result["success"] is False
    assert result["status"] == 0


def test_missing_credentials_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: None)
    result = agent._relay_http({"method": "GET", "path": "api/x"}, _cfg())
    assert result["success"] is False
    assert result["status"] == 0
    assert "credentials" in result["output"]


def test_credential_precedence_config_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("CACHED", "X"))
    cfg = _cfg(opnsense_api_key="CFGKEY", opnsense_api_secret="CFGSEC")
    assert agent._ensure_api_credentials(cfg) == ("CFGKEY", "CFGSEC")


def test_credential_precedence_cache_over_provision(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("CK", "CS"))
    monkeypatch.setattr(agent, "_provision_api_credentials", lambda: ("PK", "PS"))
    assert agent._ensure_api_credentials(_cfg(relay_provision=True)) == ("CK", "CS")


def test_provision_only_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: None)
    monkeypatch.setattr(agent, "_provision_api_credentials", lambda: ("PK", "PS"))
    assert agent._ensure_api_credentials(_cfg(relay_provision=False)) is None
    assert agent._ensure_api_credentials(_cfg(relay_provision=True)) == ("PK", "PS")


# --- request/response mapping ------------------------------------------------


def test_relay_injects_auth_and_builds_url(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_request(url, method, headers, body, timeout):
        captured.update(url=url, method=method, headers=headers, body=body)
        return 200, [("Content-Type", "application/json")], b'{"ok":1}'

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", fake_request)

    result = agent._relay_http({"method": "get", "path": "/api/core/firmware/status"}, _cfg())

    assert captured["url"] == "https://127.0.0.1:4444/api/core/firmware/status"
    assert captured["method"] == "GET"
    assert _decode_basic(captured["headers"]["Authorization"]) == ("K", "S")
    assert result["success"] is True
    assert result["status"] == 200
    assert result["headers"]["Content-Type"] == "application/json"
    assert base64.b64decode(result["body"]) == b'{"ok":1}'


def test_relay_forwards_request_body(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_request(url, method, headers, body, timeout):
        captured["body"] = body
        captured["content_length"] = headers.get("Content-Length")
        return 200, [], b""

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", fake_request)

    payload = b'{"enabled":true}'
    agent._relay_http(
        {"method": "POST", "path": "api/x", "body": base64.b64encode(payload).decode()},
        _cfg(),
    )
    assert captured["body"] == payload
    assert captured["content_length"] == str(len(payload))


def test_relay_drops_hop_by_hop_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_request(url, method, headers, body, timeout):
        captured["headers"] = headers
        # Response carries hop-by-hop + a dashboard cookie that must not leak back.
        return 200, [("Connection", "close"), ("Set-Cookie", "x=1"), ("X-Ok", "1")], b""

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", fake_request)

    result = agent._relay_http(
        {
            "method": "GET",
            "path": "api/x",
            "headers": {"Host": "evil", "Cookie": "session=abc", "Accept": "application/json"},
        },
        _cfg(),
    )
    # Inbound: Host/Cookie stripped, Accept kept, Authorization injected.
    assert "Host" not in captured["headers"]
    assert "Cookie" not in captured["headers"]
    assert captured["headers"]["Accept"] == "application/json"
    assert "Authorization" in captured["headers"]
    # Outbound: Connection stripped, other headers preserved.
    assert "Connection" not in result["headers"]
    assert result["headers"]["X-Ok"] == "1"


def test_relay_transport_error_is_status_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(agent, "_http_request", boom)

    result = agent._relay_http({"method": "GET", "path": "api/x"}, _cfg())
    assert result["success"] is False
    assert result["status"] == 0
    assert "failed" in result["output"]


def test_relay_propagates_api_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_load_cached_credentials", lambda: ("K", "S"))
    monkeypatch.setattr(
        agent, "_http_request", lambda *a, **k: (403, [], b'{"status":403}')
    )
    result = agent._relay_http({"method": "GET", "path": "api/x"}, _cfg())
    # A real API 403 is NOT a transport failure: status preserved, success False.
    assert result["status"] == 403
    assert result["success"] is False


# --- provisioning ------------------------------------------------------------


def test_provision_non_opnsense_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    assert agent._provision_api_credentials() is None


def test_provision_parses_pair_and_caches(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    cache = tmp_path / "agent.apikey"
    monkeypatch.setattr(agent, "_APIKEY_CACHE", str(cache))
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(
        agent, "_run", lambda *a, **k: json.dumps({"key": "NK", "secret": "NS"})
    )
    assert agent._provision_api_credentials() == ("NK", "NS")
    cached = json.loads(cache.read_text())
    assert cached["key"] == "NK" and cached["secret"] == "NS"


def test_provision_bad_output_returns_none(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setattr(agent, "_APIKEY_CACHE", str(tmp_path / "agent.apikey"))
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "not json")
    assert agent._provision_api_credentials() is None


# --- dispatch ----------------------------------------------------------------


def test_execute_command_dispatches_relay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "_CONFIG", _cfg(opnsense_api_key="K", opnsense_api_secret="S"))
    monkeypatch.setattr(
        agent, "_http_request", lambda *a, **k: (200, [("X", "Y")], b"hi")
    )
    result = agent.execute_command("http.relay", {"method": "GET", "path": "api/x"})
    assert result["status"] == 200
    assert base64.b64decode(result["body"]) == b"hi"
