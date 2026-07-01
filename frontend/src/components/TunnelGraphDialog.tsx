/**
 * Up/down timeline for one tunnel, shown behind the "Graph" popup on the VPN
 * overview. Reads the same transition log as the History popup but renders it as
 * plain state lines — one lane each for Phase 1, Phase 2 and Ping — green while
 * up, red while down, grey/dashed where there is no data. Phase-2 duplicates are
 * deliberately left out; this view answers only "was it up?".
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { IPsecTunnelEvent } from "../lib/types";
import { WINDOWS, autoWindowKey, axisTicks, fmtSpanTick, fmtTs } from "../lib/ipsec-history";
import {
  LANES,
  buildTimeline,
  laneNumSegments,
  laneSegments,
  type LaneState,
  type TunnelLive,
} from "../lib/ipsec-graph";
import Dialog from "./Dialog";
import StepLine from "./StepLine";

interface Props {
  instanceId: number;
  tunnelId: string;
  tunnelDescription: string;
  live: TunnelLive;
  onClose: () => void;
}

const STATE_COLOR: Record<LaneState, string> = {
  up: "#34d399",
  down: "#f87171",
  unknown: "#475569",
};

const P2_PARTIAL = "#fbbf24";

/** Phase-2 numeric line colour: green when all SAs up, red at zero, amber partial. */
function phase2Color(v: number, total: number): string {
  if (v <= 0) return STATE_COLOR.down;
  if (v >= total) return STATE_COLOR.up;
  return P2_PARTIAL;
}

// SVG geometry in user units; the viewBox scales uniformly to the dialog width.
const W = 760;
const PAD_L = 92;
const PAD_R = 20;
const PAD_T = 14;
const PAD_B = 30;
const LANE_H = 46;
const PLOT_W = W - PAD_L - PAD_R;
const PLOT_H = LANES.length * LANE_H;
const H = PAD_T + PLOT_H + PAD_B;

function LegendItem({ color, label, dashed }: { color: string; label: string; dashed?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-slate-400">
      <span
        className="inline-block h-1 w-5 rounded-full"
        style={
          dashed
            ? {
                backgroundImage: `repeating-linear-gradient(90deg, ${color} 0 3px, transparent 3px 7px)`,
              }
            : { backgroundColor: color }
        }
      />
      {label}
    </span>
  );
}

export default function TunnelGraphDialog({
  instanceId,
  tunnelId,
  tunnelDescription,
  live,
  onClose,
}: Props) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["ipsec-tunnel-history", instanceId, tunnelId],
    queryFn: () =>
      api.get<IPsecTunnelEvent[]>(
        `/api/instances/${instanceId}/ipsec/${encodeURIComponent(tunnelId)}/history?limit=500`,
      ),
  });

  // null = follow the auto-picked window; a key = user override.
  const [win, setWin] = useState<string | null>(null);
  const now = Date.now();
  const validEvents = (data ?? []).filter((ev) => !Number.isNaN(new Date(ev.ts).getTime()));
  const effectiveKey = win ?? autoWindowKey(validEvents, now);
  const winMs = WINDOWS.find((w) => w.key === effectiveKey)?.ms ?? null;

  const timeline = buildTimeline(validEvents, live);

  const firstEvent = validEvents.length
    ? Math.min(...validEvents.map((ev) => new Date(ev.ts).getTime()))
    : now - 24 * 60 * 60 * 1000;
  const rawT0 = winMs == null ? firstEvent : now - winMs;
  const t1 = now;
  const t0 = rawT0 < t1 ? rawT0 : t1 - 60_000; // guard a zero/negative span
  const span = t1 - t0;
  const x = (t: number) => PAD_L + ((t - t0) / span) * PLOT_W;

  return (
    <Dialog title={`Graph — ${tunnelDescription}`} onClose={onClose} size="xl">
      {isLoading ? (
        <p className="text-sm text-slate-500">Loading graph…</p>
      ) : isError ? (
        <p className="text-sm text-red-400">Failed to load history.</p>
      ) : (
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <div className="text-xs font-medium text-slate-400">Up/down timeline</div>
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
            aria-label={`Up/down timeline for ${tunnelDescription}`}
            className="select-none"
          >
            {axisTicks(t0, t1).map((t, i) => (
              <g key={`tick-${i}`}>
                <line
                  x1={x(t)}
                  x2={x(t)}
                  y1={PAD_T}
                  y2={PAD_T + PLOT_H}
                  stroke="#1e293b"
                  strokeWidth={1}
                  strokeDasharray="3 3"
                />
                <text
                  x={x(t)}
                  y={PAD_T + PLOT_H + 16}
                  textAnchor="middle"
                  fontSize={10}
                  fill="#64748b"
                >
                  {fmtSpanTick(t, span)}
                </text>
              </g>
            ))}

            {LANES.map((lane, li) => {
              const laneTop = PAD_T + li * LANE_H;
              const yc = laneTop + LANE_H / 2;

              // Phase 2 is a numeric step line (installed SA count), not up/down.
              if (lane.key === "phase2") {
                const total = timeline.phase2Total;
                const insetT = laneTop + 9;
                const insetB = laneTop + LANE_H - 9;
                const yForNum = (v: number) =>
                  insetB - (Math.max(0, Math.min(v, total)) / total) * (insetB - insetT);
                const numSegs = laneNumSegments(timeline.phase2Num, live.phase2_up, t0, t1);
                return (
                  <g key={lane.key}>
                    <line
                      x1={PAD_L}
                      x2={W - PAD_R}
                      y1={insetB}
                      y2={insetB}
                      stroke="#1e293b"
                      strokeWidth={1}
                    />
                    <text
                      x={PAD_L - 10}
                      y={yc}
                      textAnchor="end"
                      dominantBaseline="middle"
                      fontSize={12}
                      fill="#94a3b8"
                    >
                      {lane.label}
                    </text>
                    <text x={PAD_L + 3} y={insetB} fontSize={9} fill="#475569">
                      0
                    </text>
                    <text x={PAD_L + 3} y={insetT + 3} fontSize={9} fill="#475569">
                      {total}
                    </text>
                    <StepLine
                      segments={numSegs}
                      xFor={x}
                      yFor={yForNum}
                      strokeWidth={3}
                      colorFor={(v) => phase2Color(v, total)}
                      title={(s) =>
                        `Phase 2: ${s.value}/${total} · ${fmtTs(new Date(s.from).toISOString())} – ${fmtTs(
                          new Date(s.to).toISOString(),
                        )}`
                      }
                    />
                  </g>
                );
              }

              const segs = laneSegments(timeline[lane.key], timeline.live[lane.key], t0, t1);
              return (
                <g key={lane.key}>
                  <line
                    x1={PAD_L}
                    x2={W - PAD_R}
                    y1={yc}
                    y2={yc}
                    stroke="#1e293b"
                    strokeWidth={1}
                  />
                  <text
                    x={PAD_L - 10}
                    y={yc}
                    textAnchor="end"
                    dominantBaseline="middle"
                    fontSize={12}
                    fill="#94a3b8"
                  >
                    {lane.label}
                  </text>
                  {segs.map((s, i) => (
                    <line
                      key={`${lane.key}-${i}`}
                      x1={x(s.from)}
                      x2={x(s.to)}
                      y1={yc}
                      y2={yc}
                      stroke={STATE_COLOR[s.state]}
                      strokeWidth={5}
                      strokeLinecap={s.state === "unknown" ? "butt" : "round"}
                      strokeDasharray={s.state === "unknown" ? "2 5" : undefined}
                    >
                      <title>
                        {`${lane.label}: ${s.state} · ${fmtTs(new Date(s.from).toISOString())} – ${fmtTs(
                          new Date(s.to).toISOString(),
                        )}`}
                      </title>
                    </line>
                  ))}
                </g>
              );
            })}
          </svg>

          <div className="mt-2 flex flex-wrap items-center gap-4 text-xs">
            <span className="text-slate-500">Phase 1 / Ping:</span>
            <LegendItem color={STATE_COLOR.up} label="up" />
            <LegendItem color={STATE_COLOR.down} label="down" />
            <LegendItem color={STATE_COLOR.unknown} label="no data" dashed />
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-4 text-xs">
            <span className="text-slate-500">Phase 2 (installed SAs):</span>
            <LegendItem color={STATE_COLOR.up} label="all up" />
            <LegendItem color={P2_PARTIAL} label="partial" />
            <LegendItem color={STATE_COLOR.down} label="none" />
          </div>
        </div>
      )}
    </Dialog>
  );
}
