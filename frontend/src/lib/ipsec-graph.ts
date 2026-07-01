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

/** A numeric transition: value begins at `t` (ms epoch) and holds until the next. */
export interface NumTransition {
  t: number;
  value: number;
}

/** A drawable horizontal run holding one numeric value. */
export interface NumSegment {
  from: number;
  to: number;
  value: number;
}

/** One tunnel's contribution to an aggregate up-count: its lane + live fallback. */
export interface AggLane {
  transitions: Transition[];
  live: LaneState;
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
  /** Phase-2 installed-SA count over time (the "a" of "a/b"). */
  phase2Num: NumTransition[];
  /** Y-axis max for the Phase-2 numeric lane (configured SAs, ≥1). */
  phase2Total: number;
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

/** Parse a phase-2 "a/b" value into {up, total}, or null if it doesn't match. */
export function parsePhase2(value: string): { up: number; total: number } | null {
  const m = value.match(/^(\d+)\s*\/\s*(\d+)$/);
  if (!m) return null;
  return { up: Number(m[1]), total: Number(m[2]) };
}

/** Phase-2 "up" = all child SAs installed; new_value is "a/b". */
export function phase2Full(value: string): boolean {
  const p = parsePhase2(value);
  return p != null && p.total > 0 && p.up === p.total;
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
  const phase2Num: NumTransition[] = [];
  let p1: LaneState = "unknown";
  let p2: LaneState = "unknown";
  let pg: LaneState = "unknown";
  let p2v: number | null = null;
  let p2total = 0;
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
      const p = parsePhase2(ev.new_value);
      if (p) {
        if (p.total > p2total) p2total = p.total;
        if (p2v == null || p.up !== p2v) {
          phase2Num.push({ t, value: p.up });
          p2v = p.up;
        }
      }
    } else if (et === "ping_ok" || et === "ping_fail") {
      childUp.set(ev.child_name, et === "ping_ok");
      const anyDown = [...childUp.values()].some((v) => !v);
      const next: LaneState = childUp.size === 0 ? "unknown" : anyDown ? "down" : "up";
      push(ping, t, next, pg);
      pg = next;
    }
    // phase2_dup_on / phase2_dup_off: intentionally ignored (not an up/down signal).
  }

  const phase2Total = Math.max(1, p2total, live.phase2_total);
  return { phase1, phase2, ping, phase2Num, phase2Total, live: liveLaneStates(live) };
}

/**
 * State of one lane at instant `t`: the last transition at or before it
 * (carry-in). A lane with no transitions at all falls back to the live state (so
 * a long-stable tunnel still reads as up/down); a lane that has transitions but
 * none before `t` is genuinely "unknown" (no data yet in this window).
 */
export function stateAt(transitions: Transition[], liveState: LaneState, t: number): LaneState {
  let s: LaneState | null = null;
  for (const tr of transitions) {
    if (tr.t <= t) s = tr.state;
    else break;
  }
  if (s != null) return s;
  return transitions.length === 0 ? liveState : "unknown";
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
  const inWin = transitions.filter((tr) => tr.t > t0 && tr.t < t1).map((tr) => tr.t);
  const bounds = [t0, ...inWin, t1];
  const segs: Segment[] = [];
  for (let i = 0; i < bounds.length - 1; i++) {
    const from = bounds[i];
    const to = bounds[i + 1];
    if (to > from) segs.push({ from, to, state: stateAt(transitions, liveState, from) });
  }
  return segs;
}

/**
 * Numeric value of a lane at `t`. Carry-in like `stateAt`, but the "no data yet"
 * case returns null (a gap) — NOT 0, because for Phase 2 a real "0 installed" and
 * "no history yet" are different and both meaningful. Only a lane with zero
 * transitions falls back to the live value.
 */
export function numAt(transitions: NumTransition[], liveValue: number, t: number): number | null {
  let v: number | null = null;
  for (const tr of transitions) {
    if (tr.t <= t) v = tr.value;
    else break;
  }
  if (v != null) return v;
  return transitions.length === 0 ? liveValue : null;
}

/**
 * Slice numeric transitions into drawable segments over [t0, t1]. Regions with
 * no known value (see `numAt`) are omitted, leaving a gap in the step line.
 */
export function laneNumSegments(
  transitions: NumTransition[],
  liveValue: number,
  t0: number,
  t1: number,
): NumSegment[] {
  const inWin = transitions.filter((tr) => tr.t > t0 && tr.t < t1).map((tr) => tr.t);
  const bounds = [t0, ...inWin, t1];
  const segs: NumSegment[] = [];
  for (let i = 0; i < bounds.length - 1; i++) {
    const from = bounds[i];
    const to = bounds[i + 1];
    if (to <= from) continue;
    const value = numAt(transitions, liveValue, from);
    if (value != null) segs.push({ from, to, value });
  }
  return segs;
}

/**
 * Aggregate step function: how many lanes are "up" at each instant over [t0, t1].
 * Boundaries are the union of every lane's transitions in-window; an "unknown"
 * lane counts as not-up. Used for the all-tunnels overview graph — the value at
 * t1 must equal the live "connected" count.
 */
export function upCountSegments(lanes: AggLane[], t0: number, t1: number): NumSegment[] {
  const times = new Set<number>();
  for (const lane of lanes) {
    for (const tr of lane.transitions) {
      if (tr.t > t0 && tr.t < t1) times.add(tr.t);
    }
  }
  const bounds = [t0, ...[...times].sort((a, b) => a - b), t1];
  const segs: NumSegment[] = [];
  for (let i = 0; i < bounds.length - 1; i++) {
    const from = bounds[i];
    const to = bounds[i + 1];
    if (to <= from) continue;
    let count = 0;
    for (const lane of lanes) {
      if (stateAt(lane.transitions, lane.live, from) === "up") count++;
    }
    segs.push({ from, to, value: count });
  }
  return segs;
}
