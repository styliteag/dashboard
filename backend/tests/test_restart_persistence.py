"""Tests for backend-restart status persistence (§16 chunk B).

The hub serializes its in-memory live-status caches to a JSON snapshot on every
push and re-hydrates from it at startup, so a backend restart doesn't blank the
dashboard. Pure-logic: a fresh AgentHub() per test, DB stubbed for hydrate_from_db.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import app.agent_hub.hub as hub_mod
from app.agent_hub.converters import (
    firmware_from_agent,
    gateways_from_agent,
    ipsec_from_agent,
    status_from_agent,
)
from app.agent_hub.hub import AgentHub
from app.ipsec.history import diff_ipsec
from app.xsense.schemas import IPsecChild, IPsecServiceStatus, IPsecTunnel

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


def _ipsec_with_dup(persistent: bool) -> IPsecServiceStatus:
    child = IPsecChild(
        name="c1",
        local_ts="10.1.1.0/24",
        remote_ts="10.2.2.0/24",
        state="INSTALLED",
        dup_count=2,
        phase2_dup_persistent=persistent,
    )
    return IPsecServiceStatus(
        running=True,
        tunnels=[
            IPsecTunnel(
                id="con1",
                phase1_status="established",
                phase2_up=2,
                phase2_total=1,
                children=[child],
            )
        ],
    )


def test_hydrate_reseeds_dup_streak_no_restart_flap() -> None:
    """A restart with an active *persistent* duplicate Phase-2 must not emit a
    spurious dup-off/on flap: the in-memory streak is re-seeded from the snapshot
    so the next push re-derives persistent=True instead of resetting to 0."""
    src = AgentHub()
    src._last_status[7] = status_from_agent(SAMPLE)  # so the snapshot isn't None
    src._last_ipsec[7] = _ipsec_with_dup(True)
    snap = src._snapshot_for(7)

    h = AgentHub()  # fresh process after restart
    h.hydrate_instance(7, snap)
    prev = h.get_last_ipsec(7)
    assert prev.tunnels[0].children[0].phase2_dup_persistent is True
    assert h._ipsec_dup_streak[7]["con1|10.1.1.0/24|10.2.2.0/24"] >= 3  # re-seeded

    # Next push: the dup is still present but the agent's flag starts False; the
    # re-seeded streak must carry it straight back to persistent=True.
    new = h._annotate_dup_persistence(7, _ipsec_with_dup(False))
    assert new.tunnels[0].children[0].phase2_dup_persistent is True
    assert diff_ipsec(prev, new) == []  # no flap event


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
