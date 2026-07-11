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
