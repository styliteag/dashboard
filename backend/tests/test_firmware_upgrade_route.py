"""Route gates for the series/major upgrade endpoint (POST .../firmware/upgrade).

The action reboots a customer firewall into a new OPNsense series — every
denial path matters: out-of-scope must 404 (no existence oracle), locked
instances 409, direct-poll instances 501, and the agent target is resolved
on-box (the route sends no version parameter).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.firmware import routes as fw_routes


class FakeAgent:
    def __init__(self, success: bool = True):
        self.sent: list[tuple[str, object]] = []
        self._success = success

    async def send_command(self, action: str, params: dict | None = None, timeout: float = 30):
        self.sent.append((action, params))
        return {"success": self._success, "output": "series upgrade to 26.7 started in background"}


class FakeHub:
    def __init__(self, agent: FakeAgent | None):
        self._agent = agent

    def get(self, instance_id: int):
        return self._agent


class FakeSession:
    async def commit(self) -> None:
        pass


def _user() -> SimpleNamespace:
    return SimpleNamespace(id=1, is_superadmin=False, group_id_set=frozenset({1}))


@pytest.fixture
def quiet_audit(monkeypatch: pytest.MonkeyPatch):
    async def noop_audit(*args, **kwargs) -> None:
        pass

    monkeypatch.setattr(fw_routes, "write_audit", noop_audit)
    monkeypatch.setattr(fw_routes, "client_ip", lambda request: "127.0.0.1")


def _patch_instance(monkeypatch: pytest.MonkeyPatch, inst: object | None) -> None:
    async def fake_get(session, instance_id, user=None):
        return inst

    monkeypatch.setattr(fw_routes.inst_service, "get_instance", fake_get)


async def test_out_of_scope_instance_is_404(monkeypatch, quiet_audit) -> None:
    # get_instance(…, principal) returns None for both missing AND forbidden —
    # the route must answer 404 either way (no existence oracle).
    _patch_instance(monkeypatch, None)
    with pytest.raises(HTTPException) as exc:
        await fw_routes.firmware_upgrade(1, SimpleNamespace(), FakeSession(), _user())
    assert exc.value.status_code == 404


async def test_firmware_locked_is_409_and_agent_untouched(monkeypatch, quiet_audit) -> None:
    agent = FakeAgent()
    monkeypatch.setattr(fw_routes, "hub", FakeHub(agent))
    _patch_instance(monkeypatch, SimpleNamespace(id=1, agent_mode=True, firmware_locked=True))
    with pytest.raises(HTTPException) as exc:
        await fw_routes.firmware_upgrade(1, SimpleNamespace(), FakeSession(), _user())
    assert exc.value.status_code == 409
    assert agent.sent == []


async def test_direct_poll_instance_is_501(monkeypatch, quiet_audit) -> None:
    _patch_instance(monkeypatch, SimpleNamespace(id=1, agent_mode=False, firmware_locked=False))
    with pytest.raises(HTTPException) as exc:
        await fw_routes.firmware_upgrade(1, SimpleNamespace(), FakeSession(), _user())
    assert exc.value.status_code == 501


async def test_agent_offline_is_503(monkeypatch, quiet_audit) -> None:
    monkeypatch.setattr(fw_routes, "hub", FakeHub(None))
    _patch_instance(monkeypatch, SimpleNamespace(id=1, agent_mode=True, firmware_locked=False))
    with pytest.raises(HTTPException) as exc:
        await fw_routes.firmware_upgrade(1, SimpleNamespace(), FakeSession(), _user())
    assert exc.value.status_code == 503


async def test_dispatch_sends_no_target_version(monkeypatch, quiet_audit) -> None:
    """The upgrade target is resolved on-box (opnsense-update -vR) — the route
    must not pass any params the agent could mistake for a target."""
    agent = FakeAgent()
    monkeypatch.setattr(fw_routes, "hub", FakeHub(agent))
    _patch_instance(monkeypatch, SimpleNamespace(id=1, agent_mode=True, firmware_locked=False))
    result = await fw_routes.firmware_upgrade(1, SimpleNamespace(), FakeSession(), _user())
    assert result.success is True
    assert "26.7" in result.message
    assert [a for a, _ in agent.sent] == ["firmware.upgrade"]
    assert all(not p for _, p in agent.sent)
