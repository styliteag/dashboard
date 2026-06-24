"""Tests for the GUI-proxy tunnel registry on the hub (§18).

The registry bridges agent `tunnel` frames to the per-stream client handler queue.
End-to-end (browser/curl → firewall GUI) is proven live on .199; this guards the
routing contract.
"""

from __future__ import annotations

from app.agent_hub.gui_tunnel import GuiTunnelManager, parse_tunnel_spec
from app.agent_hub.hub import AgentHub


def test_parse_tunnel_spec() -> None:
    assert parse_tunnel_spec("3:14444,4:14445") == [(3, 14444), (4, 14445)]
    assert parse_tunnel_spec("") == []
    assert parse_tunnel_spec(" 3:14444 , bad , 5:9 ") == [(3, 14444), (5, 9)]


def test_gui_forwarder_port_is_stable_per_instance() -> None:
    # Stable convention port — never reused across instances (cross-tenant defense).
    assert GuiTunnelManager.port_for(3) == 14403
    assert GuiTunnelManager.port_for(4) == 14404
    assert GuiTunnelManager.port_for(3) != GuiTunnelManager.port_for(4)


def test_reap_idle_closes_only_long_idle_forwarders() -> None:
    import time

    from app.agent_hub.gui_tunnel import _Slot

    class _FakeServer:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    m = GuiTunnelManager()
    long_idle = _Slot(_FakeServer())
    long_idle.active, long_idle.idle_since = 0, time.monotonic() - 100
    recent_idle = _Slot(_FakeServer())
    recent_idle.active, recent_idle.idle_since = 0, time.monotonic()
    busy = _Slot(_FakeServer())
    busy.active, busy.idle_since = 1, None
    m._slots = {1: long_idle, 2: recent_idle, 3: busy}

    m.reap_idle(idle_seconds=60)

    assert 1 not in m._slots and long_idle.server.closed  # idle long enough → reaped
    assert 2 in m._slots  # idle but too recent
    assert 3 in m._slots  # has an active connection


def test_tunnel_registry_delivers_to_stream_queue() -> None:
    h = AgentHub()
    q = h.open_tunnel("s1")
    h.deliver_tunnel("s1", {"op": "data", "data": "x"})
    assert q.get_nowait() == {"op": "data", "data": "x"}


def test_deliver_unknown_stream_is_dropped() -> None:
    h = AgentHub()
    h.deliver_tunnel("ghost", {"op": "data"})  # must not raise


def test_closed_stream_stops_receiving() -> None:
    h = AgentHub()
    q = h.open_tunnel("s1")
    h.close_tunnel("s1")
    h.deliver_tunnel("s1", {"op": "data"})  # dropped — stream gone
    assert q.empty()
