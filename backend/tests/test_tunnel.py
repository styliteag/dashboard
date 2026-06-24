"""Tests for the GUI-proxy tunnel registry on the hub (§18).

The registry bridges agent `tunnel` frames to the per-stream client handler queue.
End-to-end (browser/curl → firewall GUI) is proven live on .199; this guards the
routing contract.
"""

from __future__ import annotations

from app.agent_hub.hub import AgentHub


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
