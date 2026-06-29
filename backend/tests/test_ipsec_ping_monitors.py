"""Tests for IPsec Phase-2 ping monitors: schema validation, payload + service.

DB-free: the service is exercised with a fake AsyncSession, mirroring the
project's pure-logic test style (see test_agent_ws.py).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import UniqueConstraint

import app.agent_hub.hub as hub_mod
from app.db.models import IPsecPingMonitor
from app.ipsec import ping_service
from app.ipsec.ping_schemas import PingMonitorCreate, PingMonitorUpdate, PingTestRequest

# --- schema validation -------------------------------------------------------


def test_create_requires_destination() -> None:
    with pytest.raises(ValidationError):
        PingMonitorCreate(tunnel_id="t1")  # no destination


def test_create_rejects_bad_destination() -> None:
    with pytest.raises(ValidationError):
        PingMonitorCreate(tunnel_id="t1", destination="not-an-ip")


def test_create_rejects_bad_source() -> None:
    with pytest.raises(ValidationError):
        PingMonitorCreate(tunnel_id="t1", destination="10.2.2.1", source="999.1.1.1")


def test_create_allows_empty_source() -> None:
    m = PingMonitorCreate(tunnel_id="t1", destination="10.2.2.1")
    assert m.source == ""
    assert m.ping_count == 3
    assert m.enabled is True


def test_create_strips_whitespace() -> None:
    m = PingMonitorCreate(tunnel_id="t1", destination=" 10.2.2.1 ", source=" 10.1.1.1 ")
    assert m.destination == "10.2.2.1"
    assert m.source == "10.1.1.1"


def test_ping_count_bounds() -> None:
    with pytest.raises(ValidationError):
        PingMonitorCreate(tunnel_id="t1", destination="10.2.2.1", ping_count=0)
    with pytest.raises(ValidationError):
        PingMonitorCreate(tunnel_id="t1", destination="10.2.2.1", ping_count=11)


def test_update_is_partial_and_validated() -> None:
    upd = PingMonitorUpdate(enabled=False)
    assert upd.model_dump(exclude_unset=True) == {"enabled": False}
    with pytest.raises(ValidationError):
        PingMonitorUpdate(destination="nope")


def test_ipv6_destination_accepted() -> None:
    m = PingMonitorCreate(tunnel_id="t1", destination="fd00::1")
    assert m.destination == "fd00::1"


def test_ping_test_request_validation() -> None:
    with pytest.raises(ValidationError):
        PingTestRequest(source="10.1.1.1")  # no destination
    with pytest.raises(ValidationError):
        PingTestRequest(destination="nope")
    ok = PingTestRequest(destination="10.2.2.1")
    assert ok.source == "" and ok.ping_count == 3


# --- payload builder ---------------------------------------------------------


def test_monitors_payload_shape() -> None:
    monitors = [
        SimpleNamespace(
            tunnel_id="con1",
            child_name="child-a",
            local_ts="10.1.1.0/24",
            remote_ts="10.2.2.0/24",
            source="10.1.1.1",
            destination="10.2.2.1",
            enabled=True,
            ping_count=3,
        )
    ]
    payload = ping_service.monitors_payload(monitors)
    assert payload == [
        {
            "tunnel_id": "con1",
            "child_name": "child-a",
            "local_ts": "10.1.1.0/24",
            "remote_ts": "10.2.2.0/24",
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


def test_unique_key_is_selector_pair_not_child_name() -> None:
    # strongSwan splits a multi-net Phase-2 child into sibling CHILD_SAs that share
    # one child name. Keying uniqueness on the name rejected a second monitor for a
    # different subnet of the same child (the "already exists" 409 on BadVilbel).
    # The key must be the selector pair so the siblings can each get a monitor.
    keys = {
        tuple(c.name for c in arg.columns)
        for arg in IPsecPingMonitor.__table_args__
        if isinstance(arg, UniqueConstraint)
    }
    assert ("instance_id", "tunnel_id", "local_ts", "remote_ts") in keys
    assert ("instance_id", "tunnel_id", "child_name") not in keys


@pytest.mark.asyncio
async def test_create_monitor_builds_orm_row() -> None:
    session = _FakeSession()
    data = PingMonitorCreate(
        tunnel_id="con1", child_name="c-a", destination="10.2.2.1", source="10.1.1.1"
    )
    monitor = await ping_service.create_monitor(session, 7, data)
    assert isinstance(monitor, IPsecPingMonitor)
    assert monitor.instance_id == 7
    assert monitor.tunnel_id == "con1"
    assert monitor.destination == "10.2.2.1"
    assert session.added == [monitor]


@pytest.mark.asyncio
async def test_get_monitor_rejects_wrong_instance() -> None:
    foreign = SimpleNamespace(instance_id=99)
    session = _FakeSession(get_obj=foreign)
    assert await ping_service.get_monitor(session, 7, 1) is None


@pytest.mark.asyncio
async def test_update_monitor_applies_only_set_fields() -> None:
    monitor = IPsecPingMonitor(
        instance_id=7, tunnel_id="con1", destination="10.2.2.1", source="10.1.1.1", enabled=True
    )
    session = _FakeSession()
    await ping_service.update_monitor(session, monitor, PingMonitorUpdate(enabled=False))
    assert monitor.enabled is False
    assert monitor.source == "10.1.1.1"  # untouched


@pytest.mark.asyncio
async def test_push_to_agent_noop_when_offline(monkeypatch) -> None:
    monkeypatch.setattr(hub_mod.hub, "get", lambda iid: None)
    # Must not raise even though no agent is connected.
    await ping_service.push_to_agent(_FakeSession(), 7)


@pytest.mark.asyncio
async def test_push_to_agent_sends_config_update(monkeypatch) -> None:
    sent: list[dict] = []

    class _WS:
        async def send_json(self, frame: dict) -> None:
            sent.append(frame)

    monkeypatch.setattr(hub_mod.hub, "get", lambda iid: SimpleNamespace(ws=_WS()))
    rows = [
        IPsecPingMonitor(
            instance_id=7,
            tunnel_id="con1",
            child_name="c-a",
            destination="10.2.2.1",
            source="10.1.1.1",
            enabled=True,
            ping_count=3,
        )
    ]
    await ping_service.push_to_agent(_FakeSession(rows=rows), 7)
    assert len(sent) == 1
    assert sent[0]["type"] == "config_update"
    assert sent[0]["data"]["ipsec_ping_monitors"][0]["tunnel_id"] == "con1"
