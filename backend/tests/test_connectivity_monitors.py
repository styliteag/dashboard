"""Tests for standalone connectivity ping monitors: schema validation, payload + service.

DB-free: the service is exercised with a fake AsyncSession, mirroring the project's
pure-logic test style (see test_ipsec_ping_monitors.py).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import app.agent_hub.hub as hub_mod
from app.connectivity import service as conn_service
from app.connectivity.schemas import (
    ConnMonitorCreate,
    ConnMonitorUpdate,
    ConnPingTestRequest,
)
from app.db.models import ConnectivityMonitor

# --- schema validation -------------------------------------------------------


def test_create_requires_name() -> None:
    with pytest.raises(ValidationError):
        ConnMonitorCreate(destination="10.2.2.1")  # no name


def test_create_rejects_blank_name() -> None:
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="   ", destination="10.2.2.1")


def test_create_rejects_bad_destination() -> None:
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="probe", destination="bad host")  # space → no host, no IP
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="probe", destination="999.1.1.1")  # IP-shaped typo
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="probe", destination="host..example.com")


def test_create_accepts_hostname_destination() -> None:
    m = ConnMonitorCreate(name="probe", destination=" google.com ")
    assert m.destination == "google.com"
    assert ConnMonitorCreate(name="p", destination="core-switch").destination == "core-switch"


def test_create_empty_destination_falls_back_to_name() -> None:
    m = ConnMonitorCreate(name="google.com")
    assert m.destination == "google.com"
    m = ConnMonitorCreate(name="10.2.2.1", destination="")
    assert m.destination == "10.2.2.1"
    # Name that is neither IP nor hostname → no fallback possible.
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="core switch uplink")


def test_create_rejects_bad_source() -> None:
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="probe", destination="10.2.2.1", source="999.1.1.1")
    # Source stays IP-only: ping -S needs a local address, not a name.
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="probe", destination="10.2.2.1", source="host.example.com")


def test_create_allows_empty_source_and_defaults() -> None:
    m = ConnMonitorCreate(name="probe", destination="10.2.2.1")
    assert m.source == ""
    assert m.ping_count == 3
    assert m.enabled is True


def test_create_strips_whitespace() -> None:
    m = ConnMonitorCreate(name=" probe ", destination=" 10.2.2.1 ", source=" 10.1.1.1 ")
    assert m.name == "probe"
    assert m.destination == "10.2.2.1"
    assert m.source == "10.1.1.1"


def test_ping_count_bounds() -> None:
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="p", destination="10.2.2.1", ping_count=0)
    with pytest.raises(ValidationError):
        ConnMonitorCreate(name="p", destination="10.2.2.1", ping_count=11)


def test_update_is_partial_and_validated() -> None:
    upd = ConnMonitorUpdate(enabled=False)
    assert upd.model_dump(exclude_unset=True) == {"enabled": False}
    with pytest.raises(ValidationError):
        ConnMonitorUpdate(destination="bad host")
    with pytest.raises(ValidationError):
        ConnMonitorUpdate(name="  ")


def test_update_empty_destination_falls_back_to_name() -> None:
    upd = ConnMonitorUpdate(name="google.com", destination="")
    assert upd.destination == "google.com"
    # Empty destination without a name in the same request can't fall back.
    with pytest.raises(ValidationError):
        ConnMonitorUpdate(destination="")


def test_ipv6_destination_accepted() -> None:
    m = ConnMonitorCreate(name="v6", destination="fd00::1")
    assert m.destination == "fd00::1"


def test_ping_test_request_validation() -> None:
    with pytest.raises(ValidationError):
        ConnPingTestRequest(source="10.1.1.1")  # no destination
    with pytest.raises(ValidationError):
        ConnPingTestRequest(destination="bad host")
    ok = ConnPingTestRequest(destination="10.2.2.1")
    assert ok.source == "" and ok.ping_count == 3
    assert ConnPingTestRequest(destination="google.com").destination == "google.com"


# --- payload builder ---------------------------------------------------------


def test_monitors_payload_carries_id() -> None:
    monitors = [
        SimpleNamespace(
            id=5,
            name="dns",
            source="10.1.1.1",
            destination="10.2.2.1",
            enabled=True,
            ping_count=3,
        )
    ]
    payload = conn_service.monitors_payload(monitors)
    assert payload == [
        {
            "id": 5,
            "name": "dns",
            "source": "10.1.1.1",
            "destination": "10.2.2.1",
            "enabled": True,
            "ping_count": 3,
        }
    ]


# --- service against a fake session -----------------------------------------


class _Scalars:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def all(self) -> list:
        return self._rows


class _Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)


class _FakeSession:
    def __init__(self, rows: list | None = None, get_obj: object = None) -> None:
        self._rows = rows or []
        self._get_obj = get_obj
        self.added: list = []
        self.deleted: list = []

    async def execute(self, *a, **k) -> _Result:
        return _Result(self._rows)

    async def get(self, model, pk):  # noqa: ANN001
        return self._get_obj

    def add(self, obj) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        pass

    async def delete(self, obj) -> None:
        self.deleted.append(obj)


@pytest.mark.asyncio
async def test_create_monitor_builds_orm_row() -> None:
    session = _FakeSession()
    data = ConnMonitorCreate(name="dns", destination="10.2.2.1", source="10.1.1.1")
    monitor = await conn_service.create_monitor(session, 7, data)
    assert isinstance(monitor, ConnectivityMonitor)
    assert monitor.instance_id == 7
    assert monitor.name == "dns"
    assert monitor.destination == "10.2.2.1"
    assert session.added == [monitor]


@pytest.mark.asyncio
async def test_get_monitor_rejects_wrong_instance() -> None:
    foreign = SimpleNamespace(instance_id=99)
    session = _FakeSession(get_obj=foreign)
    assert await conn_service.get_monitor(session, 7, 1) is None


@pytest.mark.asyncio
async def test_update_monitor_applies_only_set_fields() -> None:
    monitor = ConnectivityMonitor(
        instance_id=7, name="dns", destination="10.2.2.1", source="10.1.1.1", enabled=True
    )
    session = _FakeSession()
    await conn_service.update_monitor(session, monitor, ConnMonitorUpdate(enabled=False))
    assert monitor.enabled is False
    assert monitor.source == "10.1.1.1"  # untouched


@pytest.mark.asyncio
async def test_push_to_agent_noop_when_offline(monkeypatch) -> None:
    monkeypatch.setattr(hub_mod.hub, "get", lambda iid: None)
    await conn_service.push_to_agent(_FakeSession(), 7)


@pytest.mark.asyncio
async def test_push_to_agent_sends_config_update(monkeypatch) -> None:
    sent: list[dict] = []

    class _WS:
        async def send_json(self, frame: dict) -> None:
            sent.append(frame)

    monkeypatch.setattr(hub_mod.hub, "get", lambda iid: SimpleNamespace(ws=_WS()))
    rows = [
        ConnectivityMonitor(
            id=3,
            instance_id=7,
            name="dns",
            destination="10.2.2.1",
            source="10.1.1.1",
            enabled=True,
            ping_count=3,
        )
    ]
    await conn_service.push_to_agent(_FakeSession(rows=rows), 7)
    assert len(sent) == 1
    assert sent[0]["type"] == "config_update"
    assert sent[0]["data"]["connectivity_monitors"][0]["id"] == 3
