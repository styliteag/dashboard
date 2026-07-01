/**
 * Fold a tunnel's transition log (IPsecTunnelEvent[]) into up/down state lines
 * for the Graph popup. Three lanes — Phase 1, Phase 2, Ping — each a step
 * function over time. Pure and DB-free; kept out of the component file so React
 * Fast Refresh stays happy.
 *
 * The history is a *transition* log (limited, newest-first), so state is
 * reconstructed by folding the whole log ascending, then read at any instant via
 * `laneSegments` (which seeds the visible window from the last transition before
 * it — carry-in). Phase-2 duplicate events are intentionally ignored.
 *
 * Rules mirror the backend emitter (backend/src/app/ipsec/history.py):
 *   - Phase 1 up  = status contains "established" or "connected" (`_is_up`).
 *   - Phase 2 up  = every child SA installed, i.e. new_value "a/b" with a===b>0.
 *   - Ping   up   = no monitored child is failing (ping_ok/ping_fail per child).
 */
import type { IPsecChild, IPsecTunnelEvent } from "./types";
import { worstPing } from "./ipsec-ping";

export type LaneState = "up" | "down" | "unknown";
export type LaneKey = "phase1" | "phase2" | "ping";

/** A state that begins at `t` (ms epoch) and holds until the next transition. */
export interface Transition {
  t: number;
  state: LaneState;
}

/** A drawable horizontal run of one state. */
export interface Segment {
  from: number;
  to: number;
  state: LaneState;
}

/** Live tunnel snapshot used to seed lanes that have no logged transition. */
export interface TunnelLive {
  phase1_status: string;
  phase2_up: number;
  phase2_total: number;
  children: IPsecChild[];
}

export interface Timeline {
  phase1: Transition[];
  phase2: Transition[];
  ping: Transition[];
  live: Record<LaneKey, LaneState>;
}

export const LANES: { key: LaneKey; label: string }[] = [
  { key: "phase1", label: "Phase 1" },
  { key: "phase2", label: "Phase 2" },
  { key: "ping", label: "Ping" },
];

/** Phase-1 up rule — mirrors backend `_is_up`. */
export function phase1Up(status: string): boolean {
  const s = status.toLowerCase();
  return s.includes("established") || s.includes("connected");
}

/** Phase-2 "up" = all child SAs installed; new_value is "a/b". */
export function phase2Full(value: string): boolean {
  const m = value.match(/^(\d+)\s*\/\s*(\d+)$/);
  if (!m) return false;
  const up = Number(m[1]);
  const total = Number(m[2]);
  return total > 0 && up === total;
}

/** Current up/down per lane from the live tunnel row (worst-ping semantics). */
export function liveLaneStates(live: TunnelLive): Record<LaneKey, LaneState> {
  const worst = worstPing(live.children);
  const ping: LaneState = worst === "none" ? "unknown" : worst === "ok" ? "up" : "down";
  return {
    phase1: phase1Up(live.phase1_status) ? "up" : "down",
    phase2: live.phase2_total > 0 && live.phase2_up === live.phase2_total ? "up" : "down",
    ping,
  };
}

/** Fold the event log into per-lane transitions (ascending) plus the live state. */
export function buildTimeline(events: IPsecTunnelEvent[], live: TunnelLive): Timeline {
  const asc = events
    .map((ev) => ({ ev, t: new Date(ev.ts).getTime() }))
    .filter((x) => !Number.isNaN(x.t))
    .sort((a, b) => a.t - b.t);

  const phase1: Transition[] = [];
  const phase2: Transition[] = [];
  const ping: Transition[] = [];
  let p1: LaneState = "unknown";
  let p2: LaneState = "unknown";
  let pg: LaneState = "unknown";
  const childUp = new Map<string, boolean>();

  const push = (arr: Transition[], t: number, next: LaneState, prev: LaneState) => {
    if (next !== prev) arr.push({ t, state: next });
  };

  for (const { ev, t } of asc) {
    const et = ev.event_type;
    if (et === "phase1_up" || et === "phase1_down" || et === "phase1_changed") {
      const next: LaneState = phase1Up(ev.new_value) ? "up" : "down";
      push(phase1, t, next, p1);
      p1 = next;
    } else if (et === "phase2_changed") {
      const next: LaneState = phase2Full(ev.new_value) ? "up" : "down";
      push(phase2, t, next, p2);
      p2 = next;
    } else if (et === "ping_ok" || et === "ping_fail") {
      childUp.set(ev.child_name, et === "ping_ok");
      const anyDown = [...childUp.values()].some((v) => !v);
      const next: LaneState = childUp.size === 0 ? "unknown" : anyDown ? "down" : "up";
      push(ping, t, next, pg);
      pg = next;
    }
    // phase2_dup_on / phase2_dup_off: intentionally ignored (not an up/down signal).
  }

  return { phase1, phase2, ping, live: liveLaneStates(live) };
}

/**
 * Slice a lane's transitions into drawable segments over [t0, t1]. The window
 * start is seeded from the last transition at or before it (carry-in); a lane
 * with no transitions at all falls back to the live state so a long-stable
 * tunnel still draws a solid line.
 */
export function laneSegments(
  transitions: Transition[],
  liveState: LaneState,
  t0: number,
  t1: number,
): Segment[] {
  const stateAt = (t: number): LaneState => {
    let s: LaneState | null = null;
    for (const tr of transitions) {
      if (tr.t <= t) s = tr.state;
      else break;
    }
    if (s != null) return s;
    return transitions.length === 0 ? liveState : "unknown";
  };

  const inWin = transitions.filter((tr) => tr.t > t0 && tr.t < t1).map((tr) => tr.t);
  const bounds = [t0, ...inWin, t1];
  const segs: Segment[] = [];
  for (let i = 0; i < bounds.length - 1; i++) {
    const from = bounds[i];
    const to = bounds[i + 1];
    if (to > from) segs.push({ from, to, state: stateAt(from) });
  }
  return segs;
}
