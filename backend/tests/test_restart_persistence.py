"""Tests for backend-restart status persistence (§16 chunk B).

The hub serializes its in-memory live-status caches to a JSON snapshot on every
push and re-hydrates from it at startup, so a backend restart doesn't blank the
dashboard. Pure-logic: a fresh AgentHub() per test, DB stubbed for hydrate_from_db.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import app.agent_hub.hub as hub_mod
from app.agent_hub.hub import (
    AgentHub,
    firmware_from_agent,
    gateways_from_agent,
    ipsec_from_agent,
    status_from_agent,
)

SAMPLE = {
    "system": {"hostname": "fw7", "platform": "opnsense"},
    "firmware": {"product_version": "26.1.10"},
    "uptime": "1 day",
    "cpu": {"total_pct": 12.5},
    "memory": {"used_pct": 40, "total_mb": 8000, "used_mb": 3200},
    "disks": [{"device": "/dev/ada0", "mountpoint": "/", "used_pct": 50}],
    "interfaces": [
        {
            "name": "em0",
            "status": "up",
            "address": "10.0.0.1",
            "bytes_received": 1,
            "bytes_transmitted": 2,
        },
    ],
    "gateways": [{"name": "WAN", "address": "1.1.1.1", "status": "up"}],
    "ipsec": {
        "running": True,
        "tunnels": [{"id": "con1", "description": "t", "status": "established"}],
    },
    "firewall_log": [{"raw": "block in ..."}],
}


def _populate(hub: AgentHub, iid: int, *, hostname: str = "fw7") -> None:
    data = {**SAMPLE, "system": {"hostname": hostname, "platform": "opnsense"}}
    hub._last_status[iid] = status_from_agent(data)
    hub._last_gateways[iid] = gateways_from_agent(data)
    hub._last_ipsec[iid] = ipsec_from_agent(data)
    hub._last_firmware[iid] = firmware_from_agent(data, "2026-06-24T00:00:00+00:00")
    hub._last_firewall_log[iid] = data["firewall_log"]


def test_snapshot_roundtrip_through_hydrate() -> None:
    h1 = AgentHub()
    _populate(h1, 7)
    snap = h1._snapshot_for(7)

    assert snap is not None
    json.dumps(snap)  # must be JSON-serializable for the DB column

    h2 = AgentHub()  # simulate a fresh process after restart
    h2.hydrate_instance(7, snap)

    assert h2.get_last_status(7).name == "fw7"
    assert h2.get_last_status(7).cpu.total == 12.5
    assert h2.get_last_firmware(7).product_version == "26.1.10"
    assert len(h2.get_last_gateways(7)) == 1
    assert h2.get_last_ipsec(7).running is True
    assert h2.get_last_firewall_log(7) == SAMPLE["firewall_log"]


def test_snapshot_none_without_status() -> None:
    assert AgentHub()._snapshot_for(99) is None


def test_hydrate_does_not_overwrite_live_cache() -> None:
    h = AgentHub()
    _populate(h, 7, hostname="LIVE")
    # A stale snapshot from before restart must NOT clobber a fresh live push.
    stale = AgentHub()
    _populate(stale, 7, hostname="STALE")
    h.hydrate_instance(7, stale._snapshot_for(7))
    assert h.get_last_status(7).name == "LIVE"


def test_hydrate_tolerates_bad_snapshot() -> None:
    h = AgentHub()
    h.hydrate_instance(7, {"status": {"cpu": "not-a-cpu-object"}})  # fails validation
    assert h.get_last_status(7) is None  # skipped, did not raise


def test_hydrate_ignores_empty() -> None:
    h = AgentHub()
    h.hydrate_instance(7, None)
    h.hydrate_instance(7, {})
    assert h.get_last_status(7) is None


class _FakeScalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _FakeScalars(self._rows)


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *a, **k):
        return _FakeResult(self._rows)


async def test_hydrate_from_db_loads_snapshots(monkeypatch) -> None:
    src = AgentHub()
    _populate(src, 7)
    rows = [SimpleNamespace(id=7, status_snapshot=src._snapshot_for(7))]
    monkeypatch.setattr(hub_mod, "get_sessionmaker", lambda: lambda: _FakeSession(rows))

    h = AgentHub()
    n = await h.hydrate_from_db()
    assert n == 1
    assert h.get_last_status(7).name == "fw7"
