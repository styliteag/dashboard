"""Unit tests for the device transport/type abstraction (Phase 0 foundation).

DB-free: exercises the enums, the ``Instance.agent_mode`` back-compat property,
and structural conformance of ``OPNsenseClient`` to the ``DeviceClient`` protocol.
"""

from __future__ import annotations

import pytest

from app.db.models import Instance
from app.devices.protocol import DeviceClient
from app.devices.types import DeviceType, Transport
from app.xsense.client import OPNsenseClient


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


def test_instance_response_includes_transport_and_device_type() -> None:
    """The API response carries the new fields and the back-compat agent_mode."""
    from datetime import datetime
    from types import SimpleNamespace

    from app.instances.schemas import InstanceResponse

    row = SimpleNamespace(
        id=1,
        name="fw",
        base_url="https://fw.example.test",
        ssl_verify=True,
        gui_login_enabled=False,
        transport="push",
        device_type="pfsense",
        agent_mode=True,
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
    finally:
        await client.aclose()
