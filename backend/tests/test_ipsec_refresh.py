"""POST /instances/{id}/ipsec/refresh — on-demand re-check instead of the 30s wait.

Agent mode must ask the agent for a fresh snapshot (``status.refresh``) and then
serve the (just-ingested) cache; agents predating the command degrade to
last-known data instead of erroring. Direct mode is a plain live fetch.
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.ipsec.routes as ipsec_mod
import app.main as main_mod
from app.auth.deps import current_user
from app.db.base import get_session
from app.xsense.schemas import IPsecServiceStatus, IPsecTunnel


async def _noop(*a: object, **k: object) -> None:
    return None


class _Sess:
    async def commit(self) -> None:
        return None


def _app(monkeypatch, inst: object) -> object:
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)

    async def _get_instance(session: object, iid: int) -> object:
        return inst

    monkeypatch.setattr(ipsec_mod.inst_service, "get_instance", _get_instance)
    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id=1, role="admin", is_admin=True
    )
    app.dependency_overrides[get_session] = lambda: _Sess()
    return app


def _agent_instance() -> SimpleNamespace:
    return SimpleNamespace(
        id=1, deleted_at=None, transport="agent", device_type="opnsense", agent_mode=True
    )


def _status(phase1: str = "established") -> IPsecServiceStatus:
    return IPsecServiceStatus(
        running=True,
        tunnels=[IPsecTunnel(id="t1", description="tun", phase1_status=phase1)],
    )


class _FakeAgent:
    def __init__(self, result: dict):
        self.result = result
        self.calls: list[tuple[str, dict]] = []

    async def send_command(self, action: str, params: dict | None = None, timeout: float = 30):
        self.calls.append((action, params or {}))
        return self.result


def test_refresh_agent_mode_triggers_status_refresh_and_serves_cache(monkeypatch):
    agent = _FakeAgent({"success": True, "output": "snapshot pushed"})
    monkeypatch.setattr(ipsec_mod.hub, "get", lambda iid: agent)
    monkeypatch.setattr(ipsec_mod.hub, "get_last_ipsec", lambda iid: _status())
    app = _app(monkeypatch, _agent_instance())
    with TestClient(app) as c:
        r = c.post("/api/instances/1/ipsec/refresh")
    assert r.status_code == 200
    assert r.json()["tunnels"][0]["phase1_status"] == "established"
    assert agent.calls and agent.calls[0][0] == "status.refresh"


def test_refresh_agent_mode_old_agent_degrades_to_cache(monkeypatch):
    # Agent without the command answers unknown-action — still 200 + last-known.
    agent = _FakeAgent({"success": False, "output": "unknown action: status.refresh"})
    monkeypatch.setattr(ipsec_mod.hub, "get", lambda iid: agent)
    monkeypatch.setattr(ipsec_mod.hub, "get_last_ipsec", lambda iid: _status("connecting"))
    app = _app(monkeypatch, _agent_instance())
    with TestClient(app) as c:
        r = c.post("/api/instances/1/ipsec/refresh")
    assert r.status_code == 200
    assert r.json()["tunnels"][0]["phase1_status"] == "connecting"


def test_refresh_agent_mode_no_agent_is_503(monkeypatch):
    monkeypatch.setattr(ipsec_mod.hub, "get", lambda iid: None)
    app = _app(monkeypatch, _agent_instance())
    with TestClient(app) as c:
        r = c.post("/api/instances/1/ipsec/refresh")
    assert r.status_code == 503


def test_refresh_direct_mode_fetches_live(monkeypatch):
    class _Client:
        async def ipsec_status(self) -> IPsecServiceStatus:
            return _status()

        async def ipsec_connect(self, tunnel_id: str):  # satisfy SupportsIPsec
            raise NotImplementedError

        async def ipsec_disconnect(self, tunnel_id: str):
            raise NotImplementedError

        async def ipsec_restart(self):
            raise NotImplementedError

    inst = SimpleNamespace(
        id=1, deleted_at=None, transport="direct", device_type="opnsense", agent_mode=False
    )

    async def _get_client(instance: object) -> object:
        return _Client()

    monkeypatch.setattr(ipsec_mod.registry, "get", _get_client)
    app = _app(monkeypatch, inst)
    with TestClient(app) as c:
        r = c.post("/api/instances/1/ipsec/refresh")
    assert r.status_code == 200
    assert r.json()["running"] is True
