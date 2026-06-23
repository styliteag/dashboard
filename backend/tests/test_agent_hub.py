"""Tests for the agent → domain conversion in the agent hub.

These pin the contract between the agent's push payload
(agent/opnsense_agent.py collect_all) and the dashboard's domain schemas, so
drift on either side is caught. DB-free: the converters are pure.
"""

from __future__ import annotations

from app.agent_hub.hub import (
    firmware_from_agent,
    gateways_from_agent,
    ipsec_from_agent,
    status_from_agent,
)

# A realistic push matching the agent's collect_all() output shape.
AGENT_PUSH = {
    "ts": "2026-06-23T10:00:00+00:00",
    "system": {
        "hostname": "fw01",
        "os": "16.0-CURRENT",
        "platform": "pfsense",
        "agent_version": "0.2.0",
    },
    "uptime": "1d 2h 3m",
    "cpu": {"total_pct": 12.5},
    "memory": {"total_mb": 4096.0, "used_mb": 1024.0, "used_pct": 25.0},
    "disks": [{"device": "/dev/ada0", "mountpoint": "/", "used_pct": 42.0}],
    "interfaces": [
        {
            "name": "em0",
            "status": "up",
            "address": "192.168.1.1",
            "bytes_received": 100,
            "bytes_transmitted": 200,
        }
    ],
    "gateways": [
        {
            "name": "WAN",
            "address": "62.156.244.38",
            "status": "down",
            "delay": "0ms",
            "stddev": "0ms",
            "loss": "100%",
            "interface": "",
        }
    ],
    "ipsec": {
        "running": True,
        "tunnels": [
            {
                "id": "1",
                "description": "site-a",
                "remote": "1.2.3.4",
                "local": "5.6.7.8",
                "status": "established",
                "bytes_in": 500,
                "bytes_out": 600,
            }
        ],
    },
    "firmware": {
        "product_version": "26.03-RELEASE",
        "upgrade_available": False,
        "update_check_output": "Your system is up to date",
    },
    "firewall_log": [{"raw": "block in on em0"}],
}


def test_status_from_agent_maps_all_sections() -> None:
    s = status_from_agent(AGENT_PUSH)
    assert s.name == "fw01"
    assert s.version == "26.03-RELEASE"
    assert s.uptime == "1d 2h 3m"
    assert s.platform == "pfsense"
    assert s.cpu.total == 12.5
    assert s.memory.used_pct == 25.0
    assert s.memory.total_mb == 4096.0
    assert len(s.disks) == 1
    assert s.disks[0].mountpoint == "/"
    assert s.disks[0].used_pct == 42.0
    assert len(s.interfaces) == 1
    assert s.interfaces[0].name == "em0"
    assert s.interfaces[0].bytes_transmitted == 200


def test_status_from_agent_tolerates_empty_payload() -> None:
    s = status_from_agent({})
    assert s.name is None
    assert s.platform is None
    assert s.cpu.total == 0.0
    assert s.disks == []
    assert s.interfaces == []


def test_gateways_from_agent() -> None:
    gws = gateways_from_agent(AGENT_PUSH)
    assert len(gws) == 1
    assert gws[0].name == "WAN"
    assert gws[0].address == "62.156.244.38"
    assert gws[0].status == "down"
    assert gws[0].loss == "100%"
    assert gateways_from_agent({}) == []


def test_ipsec_from_agent_maps_status_to_phase1() -> None:
    ip = ipsec_from_agent(AGENT_PUSH)
    assert ip.running is True
    assert len(ip.tunnels) == 1
    t = ip.tunnels[0]
    assert t.phase1_status == "established"  # agent 'status' → phase1_status
    assert t.remote == "1.2.3.4"
    assert t.bytes_in == 500
    assert ipsec_from_agent({}).running is False


def test_firmware_from_agent_derives_updates_count() -> None:
    fw = firmware_from_agent(AGENT_PUSH, "2026-06-23T10:00:00+00:00")
    assert fw.product_version == "26.03-RELEASE"
    assert fw.upgrade_available is False
    assert fw.updates_available == 0
    assert fw.last_check == "2026-06-23T10:00:00+00:00"

    upgradable = dict(AGENT_PUSH, firmware={"product_version": "25.7", "upgrade_available": True})
    fw2 = firmware_from_agent(upgradable, "x")
    assert fw2.upgrade_available is True
    assert fw2.updates_available == 1
