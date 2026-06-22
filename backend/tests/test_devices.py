"""Unit tests for the device transport/type abstraction (Phase 0 foundation).

DB-free: exercises the enums, the ``Instance.agent_mode`` back-compat property,
and structural conformance of ``OPNsenseClient`` to the ``DeviceClient`` protocol.
"""

from __future__ import annotations

import pytest

from app.db.models import Instance
from app.devices.protocol import DeviceClient
from app.devices.types import DeviceType, Transport
from app.opnsense.client import OPNsenseClient


def test_transport_enum_values() -> None:
    assert Transport.DIRECT.value == "direct"
    assert Transport.PUSH.value == "push"
    assert Transport.RELAY.value == "relay"


def test_device_type_enum_values() -> None:
    assert DeviceType.OPNSENSE.value == "opnsense"
    assert DeviceType.PFSENSE.value == "pfsense"
    assert {DeviceType.PROXMOX, DeviceType.TRUENAS, DeviceType.QNAP} <= set(DeviceType)


def test_agent_mode_property_true_for_push() -> None:
    assert Instance(transport=Transport.PUSH.value).agent_mode is True


def test_agent_mode_property_false_for_direct() -> None:
    assert Instance(transport=Transport.DIRECT.value).agent_mode is False
    # Unset transport (pre-flush) must not read as push.
    assert Instance().agent_mode is False


@pytest.mark.asyncio
async def test_opnsense_client_satisfies_device_protocol() -> None:
    client = OPNsenseClient(base_url="https://fw.example.test", api_key="k", api_secret="s")
    try:
        assert isinstance(client, DeviceClient)
    finally:
        await client.aclose()
