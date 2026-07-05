"""Tests for the agent → domain conversion in the agent hub.

These pin the contract between the agent's push payload
(agent/orbit_agent.py collect_all) and the dashboard's domain schemas, so
drift on either side is caught. DB-free: the converters are pure.
"""

from __future__ import annotations

import pytest

from app.agent_hub.converters import (
    _child_from_agent,
    annotate_iface_error_rates,
    check_alert,
    firmware_from_agent,
    gateways_from_agent,
    ipsec_from_agent,
    pf_top_from_agent,
    status_from_agent,
)
from app.agent_hub.hub import _DUP_PERSIST_POLLS, _PING_FLAP_POLLS, AgentHub
from app.checks.history import CheckTransition
from app.checks.models import CheckState, ServiceCheck
from app.xsense.schemas import (
    InterfaceStats,
    IPsecChild,
    IPsecServiceStatus,
    IPsecTunnel,
    SystemStatus,
)


def test_check_alert_maps_state_to_level_and_check_key() -> None:
    crit = CheckTransition(check_key="cert:abc", old_state=0, new_state=2, summary="Certificate x")
    title, message, level, check_key = check_alert("opn1", crit)
    # The full check key is passed so selection can route per service, not per category.
    assert level == "error" and check_key == "cert:abc"
    assert "opn1" in title and message == "Certificate x"
    # WARN → warning, OK (recovery) → info.
    assert check_alert("opn1", CheckTransition("cpu", 0, 1, "CPU high"))[2] == "warning"
    assert check_alert("opn1", CheckTransition("memory", 2, 0, "Memory ok"))[2] == "info"


def _status_with(ifaces: list[InterfaceStats]) -> SystemStatus:
    return SystemStatus(interfaces=ifaces)


def test_iface_error_rate_needs_two_samples() -> None:
    new = _status_with([InterfaceStats(name="igb0", in_errors=10, out_errors=5)])
    # No previous snapshot → rate stays the -1.0 no-data sentinel.
    assert annotate_iface_error_rates(new, None, 30.0).interfaces[0].err_rate == -1.0


def test_iface_error_rate_derived_from_delta() -> None:
    prev = _status_with([InterfaceStats(name="igb0", in_errors=10, out_errors=5)])
    new = _status_with([InterfaceStats(name="igb0", in_errors=40, out_errors=5)])
    # (40-10)+(5-5)=30 errors over 30s → 1.0/s
    assert annotate_iface_error_rates(new, prev, 30.0).interfaces[0].err_rate == 1.0


def test_iface_error_rate_counter_reset_is_no_data() -> None:
    prev = _status_with([InterfaceStats(name="igb0", in_errors=100, out_errors=5)])
    new = _status_with([InterfaceStats(name="igb0", in_errors=2, out_errors=5)])  # rebooted
    assert annotate_iface_error_rates(new, prev, 30.0).interfaces[0].err_rate == -1.0


def test_iface_error_rate_skips_when_dt_not_positive() -> None:
    prev = _status_with([InterfaceStats(name="igb0", in_errors=10, out_errors=5)])
    new = _status_with([InterfaceStats(name="igb0", in_errors=40, out_errors=5)])
    assert annotate_iface_error_rates(new, prev, 0.0).interfaces[0].err_rate == -1.0


def test_iface_byte_rate_derived_from_delta() -> None:
    prev = _status_with([InterfaceStats(name="igb0", bytes_received=1000, bytes_transmitted=500)])
    new = _status_with([InterfaceStats(name="igb0", bytes_received=4000, bytes_transmitted=2000)])
    iface = annotate_iface_error_rates(new, prev, 30.0).interfaces[0]
    assert iface.rx_rate == 100.0  # (4000-1000)/30
    assert iface.tx_rate == 50.0  # (2000-500)/30


def test_iface_byte_rate_needs_two_samples() -> None:
    new = _status_with([InterfaceStats(name="igb0", bytes_received=1000, bytes_transmitted=500)])
    iface = annotate_iface_error_rates(new, None, 30.0).interfaces[0]
    assert iface.rx_rate == -1.0
    assert iface.tx_rate == -1.0


def test_iface_byte_rate_counter_reset_is_no_data() -> None:
    prev = _status_with([InterfaceStats(name="igb0", bytes_received=9000, bytes_transmitted=9000)])
    new = _status_with([InterfaceStats(name="igb0", bytes_received=100, bytes_transmitted=200)])
    iface = annotate_iface_error_rates(new, prev, 30.0).interfaces[0]
    assert iface.rx_rate == -1.0
    assert iface.tx_rate == -1.0


def test_iface_rates_guarded_independently() -> None:
    # rx counter advances, tx counter went backwards (a per-direction reset) → rx
    # still yields a rate, tx stays the no-data sentinel.
    prev = _status_with([InterfaceStats(name="igb0", bytes_received=1000, bytes_transmitted=9000)])
    new = _status_with([InterfaceStats(name="igb0", bytes_received=4000, bytes_transmitted=200)])
    iface = annotate_iface_error_rates(new, prev, 30.0).interfaces[0]
    assert iface.rx_rate == 100.0
    assert iface.tx_rate == -1.0


class _FakeWS:
    """Minimal stand-in for a Starlette WebSocket: register() only awaits close()."""

    def __init__(self) -> None:
        self.closed = False

    async def close(self, code: int = 1000) -> None:
        self.closed = True


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
            "address": "203.0.113.30",
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
                "unique_id": "9",
            }
        ],
    },
    "firmware": {
        "product_version": "26.03-RELEASE",
        "branch": "26.03",
        "known_branches": ["26.03"],
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
    assert gws[0].address == "203.0.113.30"
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
    assert t.unique_id == "9"  # carried through for `--terminate --ike-id` (Disconnect)
    assert ipsec_from_agent({}).running is False


def test_firmware_from_agent_derives_updates_count() -> None:
    fw = firmware_from_agent(AGENT_PUSH, "2026-06-23T10:00:00+00:00")
    assert fw.product_version == "26.03-RELEASE"
    assert fw.branch == "26.03"
    assert fw.known_branches == ["26.03"]
    assert fw.upgrade_available is False
    assert fw.updates_available == 0
    assert fw.last_check == "2026-06-23T10:00:00+00:00"

    # Older agent without product_latest: Latest falls back to installed (never blank).
    assert fw.product_latest == "26.03-RELEASE"

    upgradable = dict(
        AGENT_PUSH,
        firmware={
            "product_version": "26.1.9",
            "product_latest": "26.1.10",
            "upgrade_available": True,
        },
    )
    fw2 = firmware_from_agent(upgradable, "x")
    assert fw2.upgrade_available is True
    assert fw2.product_latest == "26.1.10"  # agent-reported available version surfaces
    assert fw2.updates_available == 1
    assert fw2.branch == ""  # not provided in override
    assert fw2.known_branches == []
    assert fw2.check_failed is False  # older agents omit it → healthy default


def test_firmware_from_agent_carries_check_failed() -> None:
    # Agent 2.6.0+: a broken update check (e.g. pkg cannot reach the repo) is
    # reported as check_failed — the verdict is "unknown", not "up to date".
    broken = dict(
        AGENT_PUSH,
        firmware={
            "product_version": "2.7.0-RELEASE",
            "upgrade_available": False,
            "check_failed": True,
            "update_check_output": "ERROR: It was not possible to determine pkg remote version",
        },
    )
    fw = firmware_from_agent(broken, "x")
    assert fw.check_failed is True
    assert fw.upgrade_available is False


# --- pf state-table insight (top talkers) -------------------------------------


# Shape produced by the agent's collect_pf_top (orbit_agent.py).
PF_TOP_PUSH = {
    "pf_top": {
        "ts": "2026-07-05T10:00:00+00:00",
        "total_states": 131,
        "top_sources": [{"ip": "10.20.0.27", "states": 2, "bytes": 56367941}],
        "top_dests": [{"ip": "224.0.0.251", "states": 20, "bytes": 200000}],
        "interfaces": [{"name": "vtnet0", "states": 10, "bytes": 613344458}],
        "protocols": [{"proto": "udp", "states": 116, "bytes": 606037803}],
        "top_flows": [
            {
                "src": "10.20.0.27",
                "sport": "5353",
                "dst": "224.0.0.251",
                "dport": "5353",
                "proto": "udp",
                "iface": "all",
                "state": "NO_TRAFFIC:SINGLE",
                "bytes": 56367149,
                "pkts": 315367,
                "age_s": 230397,
            }
        ],
    }
}


def test_pf_top_from_agent_maps_summary() -> None:
    s = pf_top_from_agent(PF_TOP_PUSH)
    assert s is not None
    assert s.total_states == 131
    assert s.top_sources[0].ip == "10.20.0.27"
    assert s.top_sources[0].bytes == 56367941
    assert s.interfaces[0].name == "vtnet0"
    assert s.protocols[0].proto == "udp"
    assert s.top_flows[0].dport == "5353"
    assert s.top_flows[0].age_s == 230397


def test_pf_top_from_agent_none_when_missing_or_malformed() -> None:
    assert pf_top_from_agent({}) is None  # older agent: no section
    assert pf_top_from_agent({"pf_top": {}}) is None
    assert pf_top_from_agent({"pf_top": "garbage"}) is None
    assert pf_top_from_agent({"pf_top": {"total_states": "not-an-int"}}) is None


def test_pf_top_hub_cache_kept_on_missing_section() -> None:
    # A push without pf_top (older agent / interval replay glitch) must not wipe
    # the cached summary — same guard style as gateways/services/certs.
    h = AgentHub()
    h._last_pf_top[5] = pf_top_from_agent(PF_TOP_PUSH)
    assert pf_top_from_agent({"system": {}}) is None
    assert h.get_last_pf_top(5).total_states == 131
    assert h.get_last_pf_top(6) is None


# --- registry identity semantics (overlapping reconnect race) -----------------


@pytest.mark.asyncio
async def test_unregister_is_identity_aware_on_overlapping_reconnect() -> None:
    """A stale OLD connection's teardown must not evict the freshly-registered NEW one."""
    h = AgentHub()
    old = await h.register(_FakeWS(), 5, "fw5")
    new = await h.register(_FakeWS(), 5, "fw5")  # reconnect: NEW replaces OLD
    assert h.get(5) is new
    assert old.ws.closed is True  # register() closed the superseded connection

    # OLD's finally-block fires after NEW registered — must be a no-op.
    h.unregister(5, old)
    assert h.get(5) is new
    assert h.is_connected(5) is True

    # NEW's own teardown removes it.
    h.unregister(5, new)
    assert h.get(5) is None


@pytest.mark.asyncio
async def test_unregister_without_agent_force_drops() -> None:
    """Admin disable/uninstall (no agent arg) drops whatever is registered."""
    h = AgentHub()
    await h.register(_FakeWS(), 7, "fw7")
    h.unregister(7)
    assert h.get(7) is None


# --- bounded tunnel queue (no unbounded buffering / OOM) ----------------------


def test_tunnel_queue_overflow_tears_down_stream() -> None:
    """A full tunnel buffer must stop buffering and close the stream, not grow."""
    from app.agent_hub.hub import _TUNNEL_QUEUE_MAX

    h = AgentHub()
    q = h.open_tunnel("s1")
    for i in range(_TUNNEL_QUEUE_MAX):
        h.deliver_tunnel("s1", {"op": "data", "data": str(i)})
    assert q.full()

    # One more frame overflows: the stream is unregistered and a close sentinel is
    # enqueued so the consumer ends cleanly (it then closes the WS + tells the agent).
    h.deliver_tunnel("s1", {"op": "data", "data": "overflow"})
    assert "s1" not in h._tunnels  # unregistered → no further buffering
    assert q.qsize() == _TUNNEL_QUEUE_MAX  # bounded: never grew past max

    drained = []
    while not q.empty():
        drained.append(q.get_nowait())
    assert drained[-1] == {"op": "close"}

    # Delivering to the now-closed stream is a no-op (no exception, no growth).
    h.deliver_tunnel("s1", {"op": "data", "data": "late"})
    assert q.empty()


# --- Duplicate Phase-2 persistence (note, not a warning) --------------------
# The agent reports an instantaneous dup_count per child; the hub only lights the
# note once the duplicate has survived _DUP_PERSIST_POLLS consecutive pushes, so a
# transient make-before-break rekey blip never shows.


def _ipsec_with_dup(dup_count: int) -> IPsecServiceStatus:
    return IPsecServiceStatus(
        running=True,
        tunnels=[
            IPsecTunnel(
                id="t1",
                children=[
                    IPsecChild(
                        local_ts="10.1.1.0/24",
                        remote_ts="10.2.2.0/24",
                        state="INSTALLED",
                        dup_count=dup_count,
                    )
                ],
            )
        ],
    )


def _dup_flag(status: IPsecServiceStatus) -> bool:
    return status.tunnels[0].children[0].phase2_dup_persistent


def test_child_from_agent_carries_dup_count() -> None:
    assert _child_from_agent({"dup_count": 3}).dup_count == 3
    assert _child_from_agent({}).dup_count == 1  # default: not a duplicate


def test_dup_persistence_lights_only_after_threshold() -> None:
    hub = AgentHub()
    # Below threshold the duplicate is present but not yet flagged persistent.
    for _ in range(_DUP_PERSIST_POLLS - 1):
        assert _dup_flag(hub._annotate_dup_persistence(1, _ipsec_with_dup(2))) is False
    # The Nth consecutive duplicate poll flips the note on.
    assert _dup_flag(hub._annotate_dup_persistence(1, _ipsec_with_dup(2))) is True


def test_dup_persistence_resets_on_a_clean_poll() -> None:
    hub = AgentHub()
    for _ in range(_DUP_PERSIST_POLLS + 2):
        hub._annotate_dup_persistence(1, _ipsec_with_dup(2))
    assert _dup_flag(hub._annotate_dup_persistence(1, _ipsec_with_dup(2))) is True
    # A single poll without the duplicate clears the streak...
    assert _dup_flag(hub._annotate_dup_persistence(1, _ipsec_with_dup(1))) is False
    # ...and the counter starts over (one dup poll is not yet persistent).
    assert _dup_flag(hub._annotate_dup_persistence(1, _ipsec_with_dup(2))) is False


def test_dup_persistence_is_isolated_per_instance() -> None:
    hub = AgentHub()
    for _ in range(_DUP_PERSIST_POLLS):
        hub._annotate_dup_persistence(1, _ipsec_with_dup(2))
    # A different instance keeps its own streak — one dup poll is not persistent.
    assert _dup_flag(hub._annotate_dup_persistence(2, _ipsec_with_dup(2))) is False


# --- Ping-monitor flap debounce ----------------------------------------------
# Each agent push is a single ping measurement; a connectivity/IPsec Phase-2 ping
# check only goes CRIT once the failure has survived _PING_FLAP_POLLS consecutive
# pushes, so a lone dropped packet never fires (and un-fires) a notification a
# few seconds later. Recovery is immediate on the first OK.


def _conn_check(state: CheckState, key: str = "connectivity:5") -> ServiceCheck:
    return ServiceCheck(key=key, state=int(state), summary="ping")


def test_ping_flap_held_at_ok_below_threshold() -> None:
    hub = AgentHub()
    for _ in range(_PING_FLAP_POLLS - 1):
        out = hub._debounce_ping_checks(1, [_conn_check(CheckState.CRIT)])
        assert out[0].state == int(CheckState.OK)


def test_ping_flap_confirms_crit_at_threshold() -> None:
    hub = AgentHub()
    for _ in range(_PING_FLAP_POLLS - 1):
        hub._debounce_ping_checks(1, [_conn_check(CheckState.CRIT)])
    out = hub._debounce_ping_checks(1, [_conn_check(CheckState.CRIT)])
    assert out[0].state == int(CheckState.CRIT)


def test_ping_flap_resets_on_a_single_ok() -> None:
    hub = AgentHub()
    for _ in range(_PING_FLAP_POLLS):
        hub._debounce_ping_checks(1, [_conn_check(CheckState.CRIT)])
    out = hub._debounce_ping_checks(1, [_conn_check(CheckState.OK)])
    assert out[0].state == int(CheckState.OK)
    # ...and the counter starts over (one fail poll is not yet confirmed).
    out = hub._debounce_ping_checks(1, [_conn_check(CheckState.CRIT)])
    assert out[0].state == int(CheckState.OK)


def test_ping_flap_is_isolated_per_instance() -> None:
    hub = AgentHub()
    for _ in range(_PING_FLAP_POLLS):
        hub._debounce_ping_checks(1, [_conn_check(CheckState.CRIT)])
    # A different instance keeps its own streak.
    out = hub._debounce_ping_checks(2, [_conn_check(CheckState.CRIT)])
    assert out[0].state == int(CheckState.OK)


def test_ping_flap_ignores_non_ping_check_keys() -> None:
    hub = AgentHub()
    # A CRIT memory/gateway/etc check is not a ping monitor — passes through as-is.
    out = hub._debounce_ping_checks(1, [_conn_check(CheckState.CRIT, key="memory")])
    assert out[0].state == int(CheckState.CRIT)


def test_ping_flap_debounces_ipsec_tunnel_ping_key_too() -> None:
    hub = AgentHub()
    key = "ipsec.tunnel_ping:site-a/10.0.0.0/24"
    out = hub._debounce_ping_checks(1, [_conn_check(CheckState.CRIT, key=key)])
    assert out[0].state == int(CheckState.OK)
