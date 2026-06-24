"""Tests for the local API relay route (/instances/{id}/relay/{path}).

Drives the real route in-process via TestClient. The connected agent is stubbed
(a fake whose send_command returns a canned relay result) and auth is overridden,
so the test needs no MariaDB, no WebSocket, and no real firewall.
"""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

import app.agent_hub.routes as routes_mod
import app.main as main_mod
from app.auth.deps import current_user


class _FakeAgent:
    """Captures send_command calls and returns a canned relay result."""

    def __init__(self, result: dict | None) -> None:
        self.result = result
        self.calls: list[tuple[str, dict]] = []

    async def send_command(self, action: str, params: dict | None = None, timeout: float = 30):
        self.calls.append((action, params or {}))
        return self.result


async def _noop(*a, **k):
    return None


def _client(monkeypatch, agent_obj) -> TestClient:
    monkeypatch.setattr(routes_mod.hub, "get", lambda iid: agent_obj)
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: object()  # bypass session auth
    return TestClient(app)


def test_agent_not_connected_returns_503(monkeypatch) -> None:
    with _client(monkeypatch, None) as client:
        r = client.get("/api/instances/7/relay/api/core/firmware/status")
    assert r.status_code == 503


def test_get_relay_maps_request_and_reconstructs_response(monkeypatch) -> None:
    agent = _FakeAgent(
        {
            "success": True,
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": base64.b64encode(b'{"ok":1}').decode(),
        }
    )
    with _client(monkeypatch, agent) as client:
        r = client.get("/api/instances/7/relay/api/core/firmware/status?x=1")

    assert r.status_code == 200
    assert r.headers["content-type"] == "application/json"
    assert r.content == b'{"ok":1}'
    # The agent was asked to relay the right method + path (query preserved).
    action, params = agent.calls[0]
    assert action == "http.relay"
    assert params["method"] == "GET"
    assert params["path"] == "api/core/firmware/status?x=1"


def test_request_body_is_forwarded_base64(monkeypatch) -> None:
    agent = _FakeAgent({"status": 200, "headers": {}, "body": ""})
    with _client(monkeypatch, agent) as client:
        client.post("/api/instances/7/relay/api/core/firmware/upgrade", json={"a": 1})
    _, params = agent.calls[0]
    assert base64.b64decode(params["body"]) == b'{"a":1}'
    assert params["method"] == "POST"


def test_write_verbs_pass_through(monkeypatch) -> None:
    # The relay must forward write methods verbatim — verified live: OPNsense alias
    # create/delete via POST, pfSense pfRest create via POST + remove via DELETE.
    for method in ("PUT", "DELETE", "PATCH"):
        agent = _FakeAgent({"status": 200, "headers": {}, "body": ""})
        with _client(monkeypatch, agent) as client:
            client.request(method, "/api/instances/7/relay/api/v2/firewall/alias?id=0")
        action, params = agent.calls[0]
        assert action == "http.relay"
        assert params["method"] == method
        assert params["path"] == "api/v2/firewall/alias?id=0"


def test_dashboard_credentials_not_forwarded(monkeypatch) -> None:
    agent = _FakeAgent({"status": 200, "headers": {}, "body": ""})
    with _client(monkeypatch, agent) as client:
        client.get(
            "/api/instances/7/relay/api/x",
            headers={"Cookie": "session=secret", "Authorization": "Bearer dash"},
        )
    _, params = agent.calls[0]
    fwd = {k.lower() for k in params["headers"]}
    assert "cookie" not in fwd  # dashboard session must not leak to the firewall
    assert "authorization" not in fwd
    assert "host" not in fwd


def test_transport_failure_status_zero_is_502(monkeypatch) -> None:
    agent = _FakeAgent({"success": False, "status": 0, "output": "connection refused"})
    with _client(monkeypatch, agent) as client:
        r = client.get("/api/instances/7/relay/api/x")
    assert r.status_code == 502
    assert "connection refused" in r.json()["detail"]


def test_command_timeout_is_502(monkeypatch) -> None:
    # send_command's timeout shape: {"success": False, "output": ...} with no status.
    agent = _FakeAgent({"success": False, "output": "command timed out"})
    with _client(monkeypatch, agent) as client:
        r = client.get("/api/instances/7/relay/api/x")
    assert r.status_code == 502


def test_upstream_error_status_passed_through(monkeypatch) -> None:
    # A real API 403 is NOT a transport failure — propagate it verbatim.
    agent = _FakeAgent(
        {"success": False, "status": 403, "headers": {}, "body": base64.b64encode(b"no").decode()}
    )
    with _client(monkeypatch, agent) as client:
        r = client.get("/api/instances/7/relay/api/x")
    assert r.status_code == 403
    assert r.content == b"no"
