"""Tests for the local API relay route (/instances/{id}/relay/{path}).

Drives the real route in-process via TestClient. The connected agent is stubbed
(a fake whose send_command returns a canned relay result) and auth is overridden,
so the test needs no MariaDB, no WebSocket, and no real firewall.
"""

from __future__ import annotations

import base64
from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.agent_hub.routes.relay as routes_mod
import app.main as main_mod
from app.auth.deps import current_user
from app.db.base import get_session


class _FakeAgent:
    """Captures send_command calls and returns a canned relay result."""

    def __init__(self, result: dict | None, platform: str = "") -> None:
        self.result = result
        self.platform = platform
        self.calls: list[tuple[str, dict]] = []

    async def send_command(self, action: str, params: dict | None = None, timeout: float = 30):
        self.calls.append((action, params or {}))
        return self.result


async def _noop(*a, **k):
    return None


class _FakeSession:
    """Serves the scoped instance lookup the relay routes now perform."""

    async def get(self, model, pk):
        return SimpleNamespace(id=pk, deleted_at=None, group_id=1)


def _client(monkeypatch, agent_obj) -> TestClient:
    monkeypatch.setattr(routes_mod.hub, "get", lambda iid: agent_obj)
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)
    app = main_mod.create_app()
    # bypass session auth with a write-capable principal so require_write passes
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id=1, role="admin", is_admin=True, is_superadmin=False, group_id_set=frozenset({1})
    )
    app.dependency_overrides[get_session] = lambda: _FakeSession()
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


# --- /relay/test: real authenticated API call via the relay ----------------


def test_relay_test_opnsense_probes_core_api(monkeypatch) -> None:
    agent = _FakeAgent(
        {"success": True, "status": 200, "headers": {}, "body": ""}, platform="opnsense"
    )
    with _client(monkeypatch, agent) as client:
        r = client.post("/api/instances/7/relay/test")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["status_code"] == 200
    assert body["latency_ms"] is not None
    action, params = agent.calls[0]
    assert action == "http.relay"
    assert params["method"] == "GET"
    assert params["path"] == "api/core/system/status"  # OPNsense authenticated endpoint


def test_relay_test_pfsense_probes_v2_api(monkeypatch) -> None:
    agent = _FakeAgent(
        {"success": True, "status": 200, "headers": {}, "body": ""}, platform="pfsense"
    )
    with _client(monkeypatch, agent) as client:
        r = client.post("/api/instances/7/relay/test")
    assert r.json()["ok"] is True
    assert agent.calls[0][1]["path"] == "api/v2/system/version"  # pfSense REST v2 endpoint


def test_relay_test_auth_failure_is_not_ok(monkeypatch) -> None:
    # A firewall 401 means the relay reached the API but credentials failed — not ok.
    # It stays server-side; a relayed 401 to the browser would trip the auto-logout.
    agent = _FakeAgent(
        {"success": False, "status": 401, "headers": {}, "body": ""}, platform="opnsense"
    )
    with _client(monkeypatch, agent) as client:
        r = client.post("/api/instances/7/relay/test")
    assert r.status_code == 200  # our endpoint succeeds; the API status is in the body
    body = r.json()
    assert body["ok"] is False
    assert body["status_code"] == 401
    assert "401" in body["error"]


def test_relay_test_transport_failure_reports_not_ok(monkeypatch) -> None:
    agent = _FakeAgent(
        {"success": False, "status": 0, "output": "connection refused"}, platform="opnsense"
    )
    with _client(monkeypatch, agent) as client:
        r = client.post("/api/instances/7/relay/test")
    assert r.status_code == 200  # the endpoint itself succeeds; the probe result is in the body
    body = r.json()
    assert body["ok"] is False
    assert "connection refused" in (body["error"] or "")


def test_relay_test_agent_not_connected(monkeypatch) -> None:
    with _client(monkeypatch, None) as client:
        r = client.post("/api/instances/7/relay/test")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "not connected" in body["error"]
