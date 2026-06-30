/**
 * Tunnel state-change history, shown behind a popup on the VPN overview.
 *
 * Reads the recorded transition log for one tunnel (phase-1 up/down, phase-2
 * count changes, per-child ping ok/fail) and renders it two ways: a colourful
 * scatter timeline (events plotted by time, grouped into lanes by category,
 * coloured per event type) on top, and the detailed newest-first text list
 * below. History is populated by the agent push, so direct-API instances (or a
 * tunnel that has never changed since rollout) show an empty state.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link2, Unlink, Activity, ArrowRight, Clock, Layers } from "lucide-react";
import {
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../lib/api";
import type { IPsecTunnelEvent } from "../lib/types";
import Dialog from "./Dialog";

interface Props {
  instanceId: number;
  tunnelId: string;
  tunnelDescription: string;
  onClose: () => void;
}

interface EventMeta {
  icon: typeof Link2;
  /** Tailwind text-colour class for the list. */
  cls: string;
  /** Hex colour for the recharts timeline (must mirror `cls`). */
  color: string;
  label: string;
  /** Vertical lane index in the scatter chart (see LANE_LABELS). */
  lane: number;
}

/** Lane labels, indexed bottom-up to match the `lane` values in metaFor. */
const LANE_LABELS = ["Ping", "Phase", "Tunnel down", "Tunnel up"];

function metaFor(ev: IPsecTunnelEvent): EventMeta {
  switch (ev.event_type) {
    case "phase1_up":
      return {
        icon: Link2,
        cls: "text-emerald-400",
        color: "#34d399",
        label: "Tunnel up",
        lane: 3,
      };
    case "phase1_down":
      return { icon: Unlink, cls: "text-red-400", color: "#f87171", label: "Tunnel down", lane: 2 };
    case "phase1_changed":
      return {
        icon: Activity,
        cls: "text-slate-300",
        color: "#cbd5e1",
        label: "Phase 1 changed",
        lane: 1,
      };
    case "phase2_changed":
      return {
        icon: Activity,
        cls: "text-amber-400",
        color: "#fbbf24",
        label: "Phase 2 changed",
        lane: 1,
      };
    case "ping_ok":
      return {
        icon: Activity,
        cls: "text-emerald-400",
        color: "#34d399",
        label: "Ping ok",
        lane: 0,
      };
    case "ping_fail":
      return { icon: Activity, cls: "text-red-400", color: "#f87171", label: "Ping fail", lane: 0 };
    case "phase2_dup_on":
      return {
        icon: Layers,
        cls: "text-amber-400",
        color: "#fbbf24",
        label: "Phase-2 duplicate",
        lane: 1,
      };
    case "phase2_dup_off":
      return {
        icon: Layers,
        cls: "text-emerald-400",
        color: "#34d399",
        label: "Phase-2 dup cleared",
        lane: 1,
      };
    default:
      return {
        icon: Activity,
        cls: "text-slate-400",
        color: "#94a3b8",
        label: ev.event_type,
        lane: 1,
      };
  }
}

function fmtTs(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function fmtAxisTime(ms: number): string {
  const d = new Date(ms);
  return Number.isNaN(d.getTime())
    ? ""
    : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

interface ChartPoint {
  x: number;
  y: number;
  color: string;
  label: string;
  child_name: string;
  old_value: string;
  new_value: string;
  ts: string;
}

interface ChartSeries {
  type: string;
  label: string;
  color: string;
  points: ChartPoint[];
}

/** Group events into one scatter series per event_type so each gets its colour. */
function buildSeries(events: IPsecTunnelEvent[]): ChartSeries[] {
  const byType = new Map<string, ChartSeries>();
  for (const ev of events) {
    const ms = new Date(ev.ts).getTime();
    if (Number.isNaN(ms)) continue;
    const m = metaFor(ev);
    let series = byType.get(ev.event_type);
    if (!series) {
      series = { type: ev.event_type, label: m.label, color: m.color, points: [] };
      byType.set(ev.event_type, series);
    }
    series.points.push({
      x: ms,
      y: m.lane,
      color: m.color,
      label: m.label,
      child_name: ev.child_name,
      old_value: ev.old_value,
      new_value: ev.new_value,
      ts: ev.ts,
    });
  }
  return [...byType.values()];
}

interface TimeWindow {
  key: string;
  label: string;
  /** Window length in ms, or null for "all". */
  ms: number | null;
}

const WINDOWS: TimeWindow[] = [
  { key: "24h", label: "24h", ms: 24 * 60 * 60 * 1000 },
  { key: "7d", label: "7d", ms: 7 * 24 * 60 * 60 * 1000 },
  { key: "30d", label: "30d", ms: 30 * 24 * 60 * 60 * 1000 },
  { key: "all", label: "All", ms: null },
];

/** Keep events newer than the window. Assumes valid timestamps (call on validEvents). */
function withinWindow(
  events: IPsecTunnelEvent[],
  nowMs: number,
  winMs: number | null,
): IPsecTunnelEvent[] {
  if (winMs == null) return events;
  const from = nowMs - winMs;
  return events.filter((ev) => new Date(ev.ts).getTime() >= from);
}

/** Narrowest window that still holds an event, so the default chart is never empty. */
function autoWindowKey(events: IPsecTunnelEvent[], nowMs: number): string {
  for (const w of WINDOWS) {
    if (w.ms == null || withinWindow(events, nowMs, w.ms).length > 0) return w.key;
  }
  return "all";
}

function EventTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: { payload: ChartPoint }[];
}) {
  if (!active || !payload || payload.length === 0) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs shadow-lg">
      <div className="font-medium" style={{ color: p.color }}>
        {p.label}
      </div>
      {p.child_name && <div className="font-mono text-slate-400">{p.child_name}</div>}
      {(p.old_value || p.new_value) && (
        <div className="font-mono text-slate-400">
          {p.old_value || "—"} → {p.new_value || "—"}
        </div>
      )}
      <div className="mt-0.5 text-slate-500">{fmtTs(p.ts)}</div>
    </div>
  );
}

export default function TunnelHistoryDialog({
  instanceId,
  tunnelId,
  tunnelDescription,
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
  const hasTimeline = validEvents.length > 0;
  const effectiveKey = win ?? autoWindowKey(validEvents, now);
  const winMs = WINDOWS.find((w) => w.key === effectiveKey)?.ms ?? null;
  const series = buildSeries(withinWindow(validEvents, now, winMs));

  return (
    <Dialog title={`History — ${tunnelDescription}`} onClose={onClose} wide>
      {isLoading ? (
        <p className="text-sm text-slate-500">Loading history…</p>
      ) : isError ? (
        <p className="text-sm text-red-400">Failed to load history.</p>
      ) : !data || data.length === 0 ? (
        <p className="text-sm text-slate-500">
          No recorded state changes yet. History is collected from agent pushes and grows as the
          tunnel changes state.
        </p>
      ) : (
        <>
          {hasTimeline && (
            <div className="mb-4 rounded-xl border border-slate-800 bg-slate-900/40 p-3">
              <div className="mb-2 flex items-center justify-between gap-2">
                <div className="text-xs font-medium text-slate-400">Event timeline</div>
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
              {series.length === 0 ? (
                <p className="py-8 text-center text-xs text-slate-500">No events in this window.</p>
              ) : (
                <ResponsiveContainer width="100%" height={190}>
                  <ScatterChart margin={{ top: 8, right: 16, bottom: 4, left: 8 }}>
                    <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      type="number"
                      dataKey="x"
                      domain={["dataMin", "dataMax"]}
                      tickFormatter={fmtAxisTime}
                      tick={{ fontSize: 10, fill: "#64748b" }}
                      stroke="#334155"
                    />
                    <YAxis
                      type="number"
                      dataKey="y"
                      domain={[-0.5, 3.5]}
                      ticks={[0, 1, 2, 3]}
                      tickFormatter={(v: number) => LANE_LABELS[v] ?? ""}
                      tick={{ fontSize: 10, fill: "#94a3b8" }}
                      width={84}
                      stroke="#334155"
                    />
                    <Tooltip content={<EventTooltip />} cursor={{ stroke: "#334155" }} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    {series.map((s) => (
                      <Scatter
                        key={s.type}
                        name={s.label}
                        data={s.points}
                        fill={s.color}
                        shape="circle"
                      />
                    ))}
                  </ScatterChart>
                </ResponsiveContainer>
              )}
            </div>
          )}
          <ul className="max-h-[50vh] space-y-2 overflow-y-auto pr-1">
            {data.map((ev, i) => {
              const s = metaFor(ev);
              const Icon = s.icon;
              return (
                <li
                  key={`${ev.ts}-${i}`}
                  className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-900/50 px-3 py-2"
                >
                  <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${s.cls}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2 text-sm">
                      <span className={`font-medium ${s.cls}`}>{s.label}</span>
                      {ev.child_name && (
                        <span className="font-mono text-xs text-slate-500">{ev.child_name}</span>
                      )}
                      {(ev.old_value || ev.new_value) && (
                        <span className="inline-flex items-center gap-1 font-mono text-xs text-slate-400">
                          {ev.old_value || "—"}
                          <ArrowRight className="h-3 w-3 text-slate-600" />
                          {ev.new_value || "—"}
                        </span>
                      )}
                    </div>
                    <div className="mt-0.5 inline-flex items-center gap-1 text-xs text-slate-500">
                      <Clock className="h-3 w-3" /> {fmtTs(ev.ts)}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </Dialog>
  );
}
