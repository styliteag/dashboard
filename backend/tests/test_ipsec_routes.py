"""IPsec routes against a Securepoint instance: status mapping + read-only actions.

Drives the real routes in-process via TestClient, with the instance fetch and the
client registry monkeypatched, and the Securepoint client backed by respx — so no
MariaDB and no real appliance are needed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import respx
from fastapi.testclient import TestClient
from httpx import Request, Response

import app.ipsec.routes as ipsec_mod
import app.main as main_mod
from app.auth.deps import current_user
from app.db.base import get_session
from app.securepoint.client import SecurepointClient

_BASE = "https://sp.example.test:11115"
_SID = "0123456789abcdef0123456789abcdef"
_IPSEC_STATUS = [
    {
        "id": 1,
        "name": "bonis-test",
        "subnet_id": 1,
        "subnet": "10.21.0.0/22 - 10.1.1.0/24",
        "local_addr": "203.0.113.10",
        "remote_addr": "203.0.113.20",
        "state": "UP",
    }
]
_APPMGMT = [{"application": "ipsec", "state": "UP", "flags": []}]


def _ok(content: object, *, sessionid: str | None = None) -> Response:
    body: dict[str, object] = {"result": {"code": 200, "status": "OK", "content": content}}
    if sessionid is not None:
        body["sessionid"] = sessionid
    return Response(200, json=body)


def _router(request: Request) -> Response:
    payload = json.loads(request.content)
    key = (payload["module"], payload["command"])
    if key == ("auth", ["login"]):
        return _ok(["session opened"], sessionid=_SID)
    if key == ("appmgmt", ["status"]):
        return _ok(_APPMGMT)
    if key == ("ipsec", ["status"]):
        return _ok(_IPSEC_STATUS)
    return _ok([])


async def _noop(*a: object, **k: object) -> None:
    return None


class _Sess:
    async def commit(self) -> None:
        return None


def _app(monkeypatch, inst: object, client: object) -> object:
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)
    monkeypatch.setattr(ipsec_mod, "write_audit", _noop)

    async def _get_instance(session: object, iid: int, principal: object = None) -> object:
        return inst

    async def _get_client(instance: object) -> object:
        return client

    monkeypatch.setattr(ipsec_mod.inst_service, "get_instance", _get_instance)
    monkeypatch.setattr(ipsec_mod.registry, "get", _get_client)
    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id=1, role="admin", is_admin=True, is_superadmin=False, group_id_set=frozenset({1})
    )
    app.dependency_overrides[get_session] = lambda: _Sess()
    return app


def _instance() -> SimpleNamespace:
    return SimpleNamespace(
        id=1,
        deleted_at=None,
        group_id=1,
        transport="direct",
        device_type="securepoint",
        agent_mode=False,
    )


def test_ipsec_status_securepoint_returns_mapped_status(monkeypatch):
    with respx.mock(base_url=_BASE) as mock:
        mock.post("/spcgi.cgi").mock(side_effect=_router)
        client = SecurepointClient(_BASE, "admin", "secret", ssl_verify=False)
        app = _app(monkeypatch, _instance(), client)
        with TestClient(app) as c:
            r = c.get("/api/instances/1/ipsec")
    assert r.status_code == 200
    body = r.json()
    assert body["running"] is True
    assert len(body["tunnels"]) == 1
    assert body["tunnels"][0]["id"] == "bonis-test"
    assert body["tunnels"][0]["phase1_status"] == "established"


def test_ipsec_connect_securepoint_returns_not_supported(monkeypatch):
    client = SecurepointClient(_BASE, "admin", "secret", ssl_verify=False)
    app = _app(monkeypatch, _instance(), client)
    with TestClient(app) as c:
        r = c.post("/api/instances/1/ipsec/connect/bonis-test")
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "read-only" in body["message"]
