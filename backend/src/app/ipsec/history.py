"""Diff successive IPsec snapshots into a per-tunnel state-change event log.

Pure and DB-free. ``diff_ipsec`` compares the previous and current
``IPsecServiceStatus`` of one instance and returns the transitions worth
remembering — Phase-1 up/down, Phase-2 installed-count changes, and per-child
ping ok/fail. The agent-push ingest (``agent_hub.hub.handle_metrics``) persists
the result so the GUI can show a tunnel's history behind a popup.

Tunnels are matched by ``id`` (the swanctl connection name) — stable across
rekeys, unlike ``unique_id`` which rotates. A tunnel/child with no prior
counterpart is skipped: with no baseline there is no transition, which also
keeps the very first push (and post-restart re-hydration) from spamming events.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.xsense.schemas import IPsecChild, IPsecServiceStatus, IPsecTunnel


def _is_up(phase1_status: str) -> bool:
    """Phase-1 considered up — same rule used by the VPN overview aggregate."""
    s = phase1_status.lower()
    return "established" in s or "connected" in s


@dataclass(frozen=True)
class TunnelEvent:
    """One recorded state transition. ``ts``/``instance_id`` are added on write."""

    tunnel_id: str
    child_name: str  # "" for tunnel-level (phase1/phase2) events
    event_type: str  # phase1_up|phase1_down|phase1_changed|phase2_changed|ping_ok|ping_fail
    old_value: str
    new_value: str


def _phase1_event(prev: IPsecTunnel, new: IPsecTunnel) -> TunnelEvent | None:
    if _is_up(prev.phase1_status) != _is_up(new.phase1_status):
        kind = "phase1_up" if _is_up(new.phase1_status) else "phase1_down"
        return TunnelEvent(new.id, "", kind, prev.phase1_status, new.phase1_status)
    if prev.phase1_status != new.phase1_status:
        return TunnelEvent(new.id, "", "phase1_changed", prev.phase1_status, new.phase1_status)
    return None


def _phase2_event(prev: IPsecTunnel, new: IPsecTunnel) -> TunnelEvent | None:
    if (prev.phase2_up, prev.phase2_total) == (new.phase2_up, new.phase2_total):
        return None
    return TunnelEvent(
        new.id,
        "",
        "phase2_changed",
        f"{prev.phase2_up}/{prev.phase2_total}",
        f"{new.phase2_up}/{new.phase2_total}",
    )


def _ping_event(tunnel_id: str, prev: IPsecChild, new: IPsecChild) -> TunnelEvent | None:
    old, cur = prev.ping_state, new.ping_state
    if old == cur or cur == "none":
        # Unchanged, or monitor removed / no data — not a tunnel-health event.
        return None
    if cur == "ok":
        return TunnelEvent(tunnel_id, new.name, "ping_ok", old, cur)
    if cur in ("fail", "error"):
        return TunnelEvent(tunnel_id, new.name, "ping_fail", old, cur)
    return None


def _tunnel_events(prev: IPsecTunnel, new: IPsecTunnel) -> list[TunnelEvent]:
    events: list[TunnelEvent] = []
    if (p1 := _phase1_event(prev, new)) is not None:
        events.append(p1)
    if (p2 := _phase2_event(prev, new)) is not None:
        events.append(p2)
    prev_children = {c.name: c for c in prev.children if c.name}
    for child in new.children:
        pc = prev_children.get(child.name)
        if pc is None:
            continue
        if (pe := _ping_event(new.id, pc, child)) is not None:
            events.append(pe)
    return events


def diff_ipsec(prev: IPsecServiceStatus | None, new: IPsecServiceStatus) -> list[TunnelEvent]:
    """Return the state transitions between two snapshots of one instance."""
    if prev is None:
        return []
    prev_by_id = {t.id: t for t in prev.tunnels}
    events: list[TunnelEvent] = []
    for tunnel in new.tunnels:
        pt = prev_by_id.get(tunnel.id)
        if pt is None:
            continue
        events.extend(_tunnel_events(pt, tunnel))
    return events
