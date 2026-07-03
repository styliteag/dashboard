"""Integration tests for the /api/ws/agent WebSocket endpoint.

Drives the real endpoint in-process via Starlette's TestClient: token auth,
hello/welcome + hub registration, and — the regression that cost hours of live
debugging — that a *failing* metrics push does NOT disconnect the agent.

The DB session and the scheduler are stubbed so the test needs no MariaDB.
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.agent_hub.hub as hub_mod
import app.agent_hub.routes.ws as routes_mod
import app.main as main_mod
from app.agent_hub.hub import hub


class _FakeResult:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one_or_none(self) -> object:
        return self._value


class _FakeSession:
    """Async-context session stub. Returns ``instance`` for the token lookup
    (execute → scalar_one_or_none) and for handle_metrics' session.get."""

    def __init__(self, instance: object, on_commit=None) -> None:
        self._instance = instance
        self._on_commit = on_commit

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *a, **k):
        return _FakeResult(self._instance)

    async def get(self, model, pk):
        return self._instance

    def add(self, obj):
        pass

    async def commit(self):
        if self._on_commit:
            self._on_commit()


async def _noop(*a, **k):
    return None


def _instance(device_type: str = "opnsense"):
    return SimpleNamespace(
        id=7,
        name="fw7",
        device_type=device_type,
        last_success_at=None,
        last_error_at=None,
        last_error_message=None,
        agent_last_seen=None,
    )


def _patch(monkeypatch, instance, on_commit=None):
    def maker():
        return _FakeSession(instance, on_commit)

    monkeypatch.setattr(routes_mod, "get_sessionmaker", lambda: maker)
    monkeypatch.setattr(hub_mod, "get_sessionmaker", lambda: maker)
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)


def test_valid_token_handshake_registers_and_unregisters(monkeypatch) -> None:
    _patch(monkeypatch, _instance())
    with (
        TestClient(main_mod.create_app()) as client,
        client.websocket_connect("/api/ws/agent", headers={"Authorization": "Bearer good"}) as ws,
    ):
        ws.send_json({"type": "hello", "agent_version": "9.9", "platform": "opnsense"})
        welcome = ws.receive_json()
        assert welcome["type"] == "welcome"
        assert welcome["instance_id"] == 7
        assert hub.is_connected(7)
        agent = hub.get(7)
        assert agent is not None
        assert agent.agent_version == "9.9"
        assert agent.platform == "opnsense"
    assert not hub.is_connected(7)  # finally: unregister on disconnect


def _handshake(client, platform: str) -> None:
    with client.websocket_connect("/api/ws/agent", headers={"Authorization": "Bearer good"}) as ws:
        ws.send_json({"type": "hello", "agent_version": "9.9", "platform": platform})
        assert ws.receive_json()["type"] == "welcome"


def test_hello_platform_corrects_wrong_device_type(monkeypatch) -> None:
    # A pfSense (Plus) box enrolled with the OPNsense creation default: the
    # agent's platform detection must self-heal the stored device kind.
    committed = []
    inst = _instance(device_type="opnsense")
    _patch(monkeypatch, inst, on_commit=lambda: committed.append(True))
    with TestClient(main_mod.create_app()) as client:
        _handshake(client, "pfsense")
    assert inst.device_type == "pfsense"
    assert committed


def test_hello_matching_platform_leaves_device_type_alone(monkeypatch) -> None:
    committed = []
    inst = _instance(device_type="pfsense")
    _patch(monkeypatch, inst, on_commit=lambda: committed.append(True))
    with TestClient(main_mod.create_app()) as client:
        _handshake(client, "pfsense")
    assert inst.device_type == "pfsense"
    assert not committed  # no needless write


def test_hello_platform_never_touches_other_device_types(monkeypatch) -> None:
    # Only the two firewall kinds the agent can detect may flip — anything else
    # stays untouched even if an agent somehow reports a platform.
    inst = _instance(device_type="proxmox")
    _patch(monkeypatch, inst)
    with TestClient(main_mod.create_app()) as client:
        _handshake(client, "pfsense")
    assert inst.device_type == "proxmox"


def test_hello_unknown_platform_ignored(monkeypatch) -> None:
    inst = _instance(device_type="opnsense")
    _patch(monkeypatch, inst)
    with TestClient(main_mod.create_app()) as client:
        _handshake(client, "unknown")
    assert inst.device_type == "opnsense"


def test_missing_token_rejected(monkeypatch) -> None:
    _patch(monkeypatch, _instance())
    with (
        TestClient(main_mod.create_app()) as client,
        client.websocket_connect("/api/ws/agent") as ws,
    ):
        assert ws.receive_json() == {"type": "error", "message": "missing token"}


def test_invalid_token_rejected(monkeypatch) -> None:
    _patch(monkeypatch, None)  # token lookup finds no instance
    with (
        TestClient(main_mod.create_app()) as client,
        client.websocket_connect("/api/ws/agent", headers={"Authorization": "Bearer nope"}) as ws,
    ):
        assert ws.receive_json() == {"type": "error", "message": "invalid token"}


def test_failing_metrics_push_does_not_disconnect(monkeypatch) -> None:
    """Regression for the silent-disconnect bug: one bad push must be tolerated."""

    def boom():
        raise RuntimeError("simulated DB failure during handle_metrics")

    _patch(monkeypatch, _instance(), on_commit=boom)
    with (
        TestClient(main_mod.create_app()) as client,
        client.websocket_connect("/api/ws/agent", headers={"Authorization": "Bearer good"}) as ws,
    ):
        ws.send_json({"type": "hello"})
        assert ws.receive_json()["type"] == "welcome"
        # This push makes handle_metrics raise (commit boom). With the old
        # 'except Exception: pass' the endpoint dropped the agent here.
        ws.send_json({"type": "metrics", "data": {"system": {}}})
        # The connection must survive — these sends would raise if it closed.
        ws.send_json({"type": "pong"})
        ws.send_json({"type": "pong"})
        assert hub.is_connected(7)
