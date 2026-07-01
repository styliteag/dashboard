/**
 * "Graph" popup for the whole VPN overview: a single step line of how many
 * tunnels have Phase 1 up over time, across every instance. Fans out one
 * per-tunnel /history query (same cache key as the per-tunnel Graph popup, so the
 * data is shared) and folds each tunnel's Phase-1 transitions into an aggregate
 * up-count. The value at "now" equals the live Connected count, and the Y-axis
 * max equals the total tunnel rows — the two on-page KPIs.
 */
import { useState } from "react";
import { useQueries } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { IPsecChild, IPsecTunnelEvent } from "../lib/types";
import { WINDOWS, autoWindowKey, axisTicks, fmtSpanTick, fmtTs } from "../lib/ipsec-history";
import { buildTimeline, upCountSegments, type AggLane } from "../lib/ipsec-graph";
import Dialog from "./Dialog";
import StepLine from "./StepLine";

/** The tunnel fields this graph needs (structurally a subset of GlobalTunnel). */
export interface AggTunnel {
  instance_id: number;
  tunnel_id: string;
  phase1_status: string;
  phase2_up: number;
  phase2_total: number;
  children: IPsecChild[];
}

interface Props {
  tunnels: AggTunnel[];
  onClose: () => void;
}

// SVG geometry in user units; the viewBox scales uniformly to the dialog width.
const W = 900;
const PAD_L = 44;
const PAD_R = 20;
const PAD_T = 16;
const PAD_B = 30;
const PLOT_W = W - PAD_L - PAD_R;
const PLOT_H = 200;
const H = PAD_T + PLOT_H + PAD_B;
const PLOT_TOP = PAD_T;
const PLOT_BOTTOM = PAD_T + PLOT_H;

/** Integer Y ticks 0..max, capped to ~6 rows for large fleets. */
function yTicks(max: number): number[] {
  const step = Math.max(1, Math.ceil(max / 5));
  const ticks: number[] = [];
  for (let v = 0; v <= max; v += step) ticks.push(v);
  if (ticks[ticks.length - 1] !== max) ticks.push(max);
  return ticks;
}

/** Aggregate up-count colour: green all up, red all down, amber in between. */
function countColor(v: number, max: number): string {
  if (v <= 0) return "#f87171";
  if (v >= max) return "#34d399";
  return "#fbbf24";
}

export default function VPNOverviewGraphDialog({ tunnels, onClose }: Props) {
  const results = useQueries({
    queries: tunnels.map((t) => ({
      queryKey: ["ipsec-tunnel-history", t.instance_id, t.tunnel_id],
      queryFn: () =>
        api.get<IPsecTunnelEvent[]>(
          `/api/instances/${t.instance_id}/ipsec/${encodeURIComponent(t.tunnel_id)}/history?limit=500`,
        ),
    })),
  });

  const [win, setWin] = useState<string | null>(null);
  const now = Date.now();
  const isLoading = results.some((r) => r.isLoading);

  // Fold each tunnel's Phase-1 transitions; keep its events for window sizing.
  const perTunnel = tunnels.map((t, i) => {
    const events = (results[i].data ?? []).filter((ev) => !Number.isNaN(new Date(ev.ts).getTime()));
    const tl = buildTimeline(events, {
      phase1_status: t.phase1_status,
      phase2_up: t.phase2_up,
      phase2_total: t.phase2_total,
      children: t.children,
    });
    const lane: AggLane = { transitions: tl.phase1, live: tl.live.phase1 };
    return { events, lane };
  });

  const allEvents = perTunnel.flatMap((p) => p.events);
  const effectiveKey = win ?? autoWindowKey(allEvents, now);
  const winMs = WINDOWS.find((w) => w.key === effectiveKey)?.ms ?? null;

  const firstEvent = allEvents.length
    ? Math.min(...allEvents.map((ev) => new Date(ev.ts).getTime()))
    : now - 24 * 60 * 60 * 1000;
  const rawT0 = winMs == null ? firstEvent : now - winMs;
  const t1 = now;
  const t0 = rawT0 < t1 ? rawT0 : t1 - 60_000; // guard a zero/negative span
  const span = t1 - t0;
  const x = (t: number) => PAD_L + ((t - t0) / span) * PLOT_W;

  const maxY = Math.max(1, tunnels.length);
  const yFor = (v: number) =>
    PLOT_BOTTOM - (Math.max(0, Math.min(v, maxY)) / maxY) * (PLOT_BOTTOM - PLOT_TOP);
  const segs = upCountSegments(
    perTunnel.map((p) => p.lane),
    t0,
    t1,
  );
  const nowUp = segs.length ? segs[segs.length - 1].value : 0;

  return (
    <Dialog title="Graph — tunnels up (all instances)" onClose={onClose} size="2xl">
      {isLoading ? (
        <p className="text-sm text-slate-500">Loading graph…</p>
      ) : tunnels.length === 0 ? (
        <p className="text-sm text-slate-500">No tunnels to graph.</p>
      ) : (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <div className="text-xs font-medium text-slate-400">
              Tunnels with Phase 1 up · now {nowUp}/{maxY}
            </div>
            <div className="flex gap-1">
              {WINDOWS.map((w) => (
                <button
                  key={w.key}
                  type="button"
                  onClick={() => setWin(w.key)}
                  className={`rounded px-2 py-0.5 text-xs transition-colors ${
                    effectiveKey === w.key
                      ? "bg-slate-700 text-slate-100"
                      : "text-slate-500 hover:text-slate-300"
                  }`}
                >
                  {w.label}
                </button>
              ))}
            </div>
          </div>

          <svg
            viewBox={`0 0 ${W} ${H}`}
            width="100%"
            role="img"
            aria-label="Number of tunnels up over time"
            className="select-none"
          >
            {yTicks(maxY).map((v) => (
              <g key={`y-${v}`}>
                <line
                  x1={PAD_L}
                  x2={W - PAD_R}
                  y1={yFor(v)}
                  y2={yFor(v)}
                  stroke="#1e293b"
                  strokeWidth={1}
                />
                <text
                  x={PAD_L - 8}
                  y={yFor(v)}
                  textAnchor="end"
                  dominantBaseline="middle"
                  fontSize={10}
                  fill="#64748b"
                >
                  {v}
                </text>
              </g>
            ))}

            {axisTicks(t0, t1).map((t, i) => (
              <text
                key={`x-${i}`}
                x={x(t)}
                y={PLOT_BOTTOM + 16}
                textAnchor="middle"
                fontSize={10}
                fill="#64748b"
              >
                {fmtSpanTick(t, span)}
              </text>
            ))}

            <StepLine
              segments={segs}
              xFor={x}
              yFor={yFor}
              strokeWidth={3}
              colorFor={(v) => countColor(v, maxY)}
              title={(s) =>
                `${s.value}/${maxY} up · ${fmtTs(new Date(s.from).toISOString())} – ${fmtTs(
                  new Date(s.to).toISOString(),
                )}`
              }
            />
          </svg>

          <p className="mt-2 text-xs text-slate-500">
            One line for the whole fleet. Each tunnel end is counted separately (matching the
            Connected / total KPIs); direct-API instances with no history hold their current state
            across the window.
          </p>
        </div>
      )}
    </Dialog>
  );
}
