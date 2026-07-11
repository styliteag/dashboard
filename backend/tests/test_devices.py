"""Unit tests for the device transport/type abstraction (Phase 0 foundation).

DB-free: exercises the enums, the ``Instance.agent_mode`` back-compat property,
and structural conformance of ``OPNsenseClient`` to the ``DeviceClient`` protocol.
"""

from __future__ import annotations

import pytest

from app.db.models import Instance
from app.devices.protocol import DeviceClient, SupportsIPsec
from app.devices.types import DeviceType, Transport
from app.securepoint.client import SecurepointClient
from app.xsense.client import OPNsenseClient


def test_transport_enum_values() -> None:
    assert Transport.DIRECT.value == "direct"
    assert Transport.PUSH.value == "push"
    assert Transport.RELAY.value == "relay"


def test_device_type_enum_values() -> None:
    assert DeviceType.OPNSENSE.value == "opnsense"
    assert DeviceType.PFSENSE.value == "pfsense"
    assert DeviceType.SECUREPOINT.value == "securepoint"
    assert {DeviceType.PROXMOX, DeviceType.TRUENAS, DeviceType.QNAP} <= set(DeviceType)


def test_agent_mode_property_true_for_push() -> None:
    assert Instance(transport=Transport.PUSH.value).agent_mode is True


def test_agent_mode_property_false_for_direct() -> None:
    assert Instance(transport=Transport.DIRECT.value).agent_mode is False
    # Unset transport (pre-flush) must not read as push.
    assert Instance().agent_mode is False


def test_instance_response_includes_transport_and_device_type() -> None:
    """The API response carries the new fields and the back-compat agent_mode."""
    from datetime import datetime
    from types import SimpleNamespace

    from app.instances.schemas import InstanceResponse

    row = SimpleNamespace(
        id=1,
        name="fw",
        group_id=1,
        slug="fw",
        base_url="https://fw.example.test",
        ssl_verify=True,
        gui_login_enabled=False,
        shell_enabled=False,
        transport="push",
        device_type="pfsense",
        agent_mode=True,
        ssh_enabled=False,
        ssh_port=9922,
        ssh_user="root",
        ssh_key_set=False,
        ssh_host_key_pinned=False,
        agent_last_seen=None,
        location=None,
        notes=None,
        tags=None,
        last_success_at=None,
        last_error_at=None,
        last_error_message=None,
        created_at=datetime(2026, 1, 1),
        updated_at=datetime(2026, 1, 1),
    )
    resp = InstanceResponse.model_validate(row)
    assert resp.transport == "push"
    assert resp.device_type == "pfsense"
    assert resp.agent_mode is True


@pytest.mark.asyncio
async def test_opnsense_client_satisfies_device_protocol() -> None:
    client = OPNsenseClient(base_url="https://fw.example.test", api_key="k", api_secret="s")
    try:
        assert isinstance(client, DeviceClient)
        assert isinstance(client, SupportsIPsec)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_securepoint_client_satisfies_protocols() -> None:
    client = SecurepointClient(base_url="https://sp.example.test:11115", user="u", password="p")
    try:
        assert isinstance(client, DeviceClient)
        assert isinstance(client, SupportsIPsec)
    finally:
        await client.aclose()


def test_device_caps_covers_every_device_type() -> None:
    """DR-8: a new DeviceType member without a capability row must fail loudly."""
    from app.devices.capabilities import DEVICE_CAPS

    assert set(DEVICE_CAPS) == set(DeviceType)


def test_device_caps_securepoint_is_direct_only() -> None:
    from app.devices.capabilities import device_caps

    caps = device_caps(DeviceType.SECUREPOINT)
    assert caps.agent is False
    assert caps.capture is False
    assert caps.connectivity is False
    assert caps.ssh_enrichment is True
    assert caps.tunnels is True


def test_device_caps_firewall_rules_only_opnsense() -> None:
    from app.devices.capabilities import DEVICE_CAPS, device_caps

    assert device_caps("opnsense").firewall_rules is True
    others = [t for t in DeviceType if t is not DeviceType.OPNSENSE]
    assert all(DEVICE_CAPS[t].firewall_rules is False for t in others)


def test_device_caps_unknown_value_falls_back_to_defaults() -> None:
    """Legacy/unknown device_type strings must behave like today (all tabs shown)."""
    from app.devices.capabilities import device_caps

    caps = device_caps("something-legacy")
    assert caps.agent is True
    assert caps.firewall_rules is False
    assert device_caps(None).agent is True


def test_device_caps_rows_are_immutable() -> None:
    import dataclasses

    from app.devices.capabilities import device_caps

    with pytest.raises(dataclasses.FrozenInstanceError):
        device_caps("opnsense").agent = False  # type: ignore[misc]


# --- Generic Linux node (§25, DR-9): push-only, agent-collected -----------------


def test_device_caps_linux_is_push_only() -> None:
    from app.devices.capabilities import device_caps

    caps = device_caps(DeviceType.LINUX)
    assert caps.agent is True
    assert caps.direct_api is False
    assert caps.tunnels is False
    assert caps.webif is False
    assert caps.firewall_rules is False
    assert caps.updates_label == "Updates"
    assert caps.default_push_interval == 120


def test_instance_create_linux_defaults_push_and_interval() -> None:
    """linux: no base_url needed; transport forced to push; 120s push default."""
    from app.instances.schemas import InstanceCreate

    m = InstanceCreate(name="srv", device_type=DeviceType.LINUX)
    assert m.transport is Transport.PUSH
    assert m.base_url == ""
    assert m.push_interval_seconds == 120


def test_instance_create_linux_explicit_interval_wins() -> None:
    from app.instances.schemas import InstanceCreate

    m = InstanceCreate(name="srv", device_type=DeviceType.LINUX, push_interval_seconds=30)
    assert m.push_interval_seconds == 30


def test_instance_create_linux_rejects_base_url_and_direct_transport() -> None:
    from pydantic import ValidationError

    from app.instances.schemas import InstanceCreate

    with pytest.raises(ValidationError):
        InstanceCreate(name="srv", device_type=DeviceType.LINUX, base_url="https://x.example")
    with pytest.raises(ValidationError):
        InstanceCreate(name="srv", device_type=DeviceType.LINUX, transport=Transport.DIRECT)


def test_instance_create_direct_types_still_require_base_url() -> None:
    from pydantic import ValidationError

    from app.instances.schemas import InstanceCreate

    with pytest.raises(ValidationError):
        InstanceCreate(name="fw", device_type=DeviceType.OPNSENSE)


@pytest.mark.asyncio
async def test_test_connection_pings_agent_for_push_only_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """linux (§25): test-connection probes the agent WS round-trip, not a URL."""
    from types import SimpleNamespace

    from app.agent_hub.hub import hub
    from app.instances.service import test_connection

    inst = Instance(device_type="linux")
    inst.id = 6

    # No connected agent → honest failure, no client construction attempted.
    monkeypatch.setattr(hub, "get", lambda _id: None)
    ok, status_code, latency, error = await test_connection(inst)
    assert ok is False and status_code is None
    assert "agent not connected" in (error or "")

    async def pong(action: str, params: dict, timeout: float = 10) -> dict:
        assert action == "ping"
        return {"success": True, "output": "pong"}

    monkeypatch.setattr(hub, "get", lambda _id: SimpleNamespace(send_command=pong))
    ok, _status, latency, error = await test_connection(inst)
    assert ok is True and error is None
    assert latency is not None and latency >= 0


def test_registry_refuses_client_for_push_only_type() -> None:
    from app.xsense.registry import ClientRegistry

    with pytest.raises(ValueError, match="no direct API client"):
        ClientRegistry._build(Instance(device_type="linux", base_url=""))


@pytest.mark.asyncio
async def test_sync_device_type_heals_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """An agent reporting platform=linux corrects a default-typed instance."""
    from types import SimpleNamespace

    from app.agent_hub.routes import ws as ws_routes

    inst = SimpleNamespace(device_type="opnsense")
    committed: list[bool] = []

    class _FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, model, pk):
            return inst

        async def commit(self):
            committed.append(True)

    monkeypatch.setattr(ws_routes, "get_sessionmaker", lambda: lambda: _FakeSession())
    await ws_routes._sync_device_type(1, "linux")
    assert inst.device_type == "linux" and committed

    # Securepoint must never flip on an agent's word.
    inst2 = SimpleNamespace(device_type="securepoint")

    class _FakeSession2(_FakeSession):
        async def get(self, model, pk):
            return inst2

    monkeypatch.setattr(ws_routes, "get_sessionmaker", lambda: lambda: _FakeSession2())
    await ws_routes._sync_device_type(1, "linux")
    assert inst2.device_type == "securepoint"
