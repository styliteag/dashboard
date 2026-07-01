/**
 * Pure time helpers shared by the tunnel History and Graph popups. Kept out of
 * the component files so both dialogs use one definition (and so React Fast
 * Refresh stays happy — a component module should export only components).
 */
import type { IPsecTunnelEvent } from "./types";

export interface TimeWindow {
  key: string;
  label: string;
  /** Window length in ms, or null for "all". */
  ms: number | null;
}

export const WINDOWS: TimeWindow[] = [
  { key: "24h", label: "24h", ms: 24 * 60 * 60 * 1000 },
  { key: "7d", label: "7d", ms: 7 * 24 * 60 * 60 * 1000 },
  { key: "30d", label: "30d", ms: 30 * 24 * 60 * 60 * 1000 },
  { key: "all", label: "All", ms: null },
];

/** Keep events newer than the window. Assumes valid timestamps (call on validEvents). */
export function withinWindow(
  events: IPsecTunnelEvent[],
  nowMs: number,
  winMs: number | null,
): IPsecTunnelEvent[] {
  if (winMs == null) return events;
  const from = nowMs - winMs;
  return events.filter((ev) => new Date(ev.ts).getTime() >= from);
}

/** Narrowest window that still holds an event, so the default view is never empty. */
export function autoWindowKey(events: IPsecTunnelEvent[], nowMs: number): string {
  for (const w of WINDOWS) {
    if (w.ms == null || withinWindow(events, nowMs, w.ms).length > 0) return w.key;
  }
  return "all";
}

/** Absolute timestamp for tooltips / list rows. */
export function fmtTs(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** recharts axis tick: time-of-day. Single-arg on purpose — recharts passes (value, index). */
export function fmtAxisTime(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime())
    ? ""
    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** N+1 evenly spaced tick times across [t0, t1] (endpoints included). */
export function axisTicks(t0: number, t1: number, n = 5): number[] {
  return Array.from({ length: n + 1 }, (_, i) => t0 + ((t1 - t0) * i) / n);
}

/** Span-aware tick: date for multi-day spans, otherwise time-of-day. */
export function fmtSpanTick(ms: number, spanMs: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  if (spanMs > 2 * 24 * 60 * 60 * 1000) {
    return d.toLocaleDateString([], { month: "short", day: "2-digit" });
  }
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
