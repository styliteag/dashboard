"""Bulk action route: firmware_update support + agent-mode dispatch via the hub.

Drives the real /api/bulk/action route in-process via TestClient with the DB
session, auth, audit, client registry and agent hub monkeypatched — no MariaDB
and no real appliance needed.
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.bulk.routes as bulk_mod
import app.main as main_mod
from app.auth.deps import require_write
from app.db.base import get_session


class _Result:
    def __init__(self, instances: list) -> None:
        self._instances = instances

    def scalars(self) -> _Result:
        return self

    def all(self) -> list:
        return self._instances


class _Sess:
    def __init__(self, instances: list) -> None:
        self._instances = instances

    async def execute(self, _stmt: object) -> _Result:
        return _Result(self._instances)

    async def commit(self) -> None:
        return None


async def _noop(*a: object, **k: object) -> None:
    return None


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def firmware_update(self) -> SimpleNamespace:
        self.calls.append("firmware_update")
        return SimpleNamespace(success=True, message="update started")

    async def firmware_check(self) -> SimpleNamespace:
        self.calls.append("firmware_check")
        return SimpleNamespace(success=True, message="check done")


class _FakeAgent:
    def __init__(self, result: dict | None = None) -> None:
        self.commands: list[tuple[str, float]] = []
        self._result = result or {"success": True, "output": "update started in background"}

    async def send_command(
        self, action: str, params: dict | None = None, timeout: float = 30
    ) -> dict:
        self.commands.append((action, timeout))
        return self._result


def _inst(iid: int, name: str, agent_mode: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        id=iid,
        name=name,
        deleted_at=None,
        agent_mode=agent_mode,
        device_type="opnsense",
        transport="direct",
        firmware_locked=False,
    )


def _app(monkeypatch, instances: list) -> object:
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(bulk_mod, "write_audit", _noop)
    app = main_mod.create_app()
    app.dependency_overrides[require_write] = lambda: SimpleNamespace(
        id=1, role="admin", is_admin=True
    )
    app.dependency_overrides[get_session] = lambda: _Sess(instances)
    return app


def test_bulk_firmware_update_polling_instance(monkeypatch) -> None:
    client = _FakeClient()

    async def _get(instance: object) -> _FakeClient:
        return client

    monkeypatch.setattr(bulk_mod.registry, "get", _get)
    app = _app(monkeypatch, [_inst(1, "opn1")])
    with TestClient(app) as c:
        r = c.post("/api/bulk/action", json={"instance_ids": [1], "action": "firmware_update"})
    assert r.status_code == 200
    body = r.json()
    assert body["succeeded"] == 1 and body["failed"] == 0
    assert client.calls == ["firmware_update"]


def test_bulk_firmware_update_agent_mode_dispatches_via_hub(monkeypatch) -> None:
    agent = _FakeAgent()
    monkeypatch.setattr(bulk_mod.hub, "get", lambda iid: agent)
    app = _app(monkeypatch, [_inst(1, "opn1", agent_mode=True)])
    with TestClient(app) as c:
        r = c.post("/api/bulk/action", json={"instance_ids": [1], "action": "firmware_update"})
    body = r.json()
    assert body["succeeded"] == 1 and body["failed"] == 0
    assert agent.commands[0][0] == "firmware.update"


def test_bulk_agent_mode_not_connected_fails_gracefully(monkeypatch) -> None:
    monkeypatch.setattr(bulk_mod.hub, "get", lambda iid: None)
    app = _app(monkeypatch, [_inst(1, "opn1", agent_mode=True)])
    with TestClient(app) as c:
        r = c.post("/api/bulk/action", json={"instance_ids": [1], "action": "firmware_update"})
    body = r.json()
    assert body["failed"] == 1 and body["succeeded"] == 0
    assert "not connected" in body["results"][0]["message"]


def test_bulk_firmware_check_agent_mode_uses_hub(monkeypatch) -> None:
    agent = _FakeAgent({"success": True, "output": "your system is up to date"})
    monkeypatch.setattr(bulk_mod.hub, "get", lambda iid: agent)
    app = _app(monkeypatch, [_inst(1, "opn1", agent_mode=True)])
    with TestClient(app) as c:
        r = c.post("/api/bulk/action", json={"instance_ids": [1], "action": "firmware_check"})
    body = r.json()
    assert body["succeeded"] == 1
    assert agent.commands[0][0] == "firmware.check"


def test_bulk_unknown_action_fails_per_instance(monkeypatch) -> None:
    app = _app(monkeypatch, [_inst(1, "opn1"), _inst(2, "opn2", agent_mode=True)])
    monkeypatch.setattr(bulk_mod.hub, "get", lambda iid: _FakeAgent())
    with TestClient(app) as c:
        r = c.post("/api/bulk/action", json={"instance_ids": [1, 2], "action": "nonsense"})
    body = r.json()
    assert body["failed"] == 2 and body["succeeded"] == 0
