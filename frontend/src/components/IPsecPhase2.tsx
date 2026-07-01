/**
 * Shared Phase-2 (child SA) UI: status badges + the per-child detail list with
 * the ping-monitor affordance. Used by both the instance IPsec view and the
 * global VPN overview so Phase 2 + its ping status look identical everywhere.
 */
import { Activity, Copy, Settings2 } from "lucide-react";
import type { IPsecChild, IPsecPingMonitor } from "../lib/types";
import { findMonitor, worstPing } from "../lib/ipsec-ping";

/** A child whose duplicate Phase-2 has persisted across polls (note, not a warning). */
function isDup(ch: IPsecChild): boolean {
  return Boolean(ch.phase2_dup_persistent);
}

/**
 * Always-visible per-tunnel ping rollup, so a failing probe shows RED on the row
 * itself — the whole point is catching "SA installed but not passing traffic"
 * without having to expand. Null when no child has a monitor configured.
 */
export function PingSummary({ entries }: { entries: IPsecChild[] }) {
  const w = worstPing(entries);
  if (w === "none") return null;
  const map: Record<string, { cls: string; label: string }> = {
    ok: { cls: "bg-emerald-600/20 text-emerald-400", label: "ping ok" },
    error: { cls: "bg-amber-600/20 text-amber-400", label: "ping error" },
    fail: { cls: "bg-red-600/20 text-red-400", label: "ping fail" },
  };
  const m = map[w];
  return (
    <span
      title="Worst Phase-2 ping result on this tunnel — expand for per-selector detail"
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-xs ${m.cls}`}
    >
      <Activity className="h-3 w-3" />
      {m.label}
    </span>
  );
}

/**
 * Always-visible note when one or more Phase-2 selectors carry a persistent
 * duplicate (more than one INSTALLED child SA for the same selector pair).
 * Neutral/info styling on purpose — it is a note, not a warning. Null when none.
 */
export function Phase2DupNote({ entries }: { entries: IPsecChild[] }) {
  const dups = entries.filter(isDup);
  if (dups.length === 0) return null;
  const noun = dups.length > 1 ? "selectors have" : "selector has";
  return (
    <span
      title={`${dups.length} Phase-2 ${noun} more than one installed child SA (duplicate), persisting across polls — expand for detail`}
      className="inline-flex items-center gap-1 whitespace-nowrap rounded bg-sky-600/20 px-1.5 py-0.5 text-xs text-sky-300"
    >
      <Copy className="h-3 w-3" />
      dup
    </span>
  );
}

/** "x/n" badge — red none up, amber partial, green all up. */
export function Phase2Badge({ up, total }: { up: number; total: number }) {
  if (total <= 0) return <span className="text-xs text-slate-600">—</span>;
  const cls =
    up === 0
      ? "bg-red-600/20 text-red-400"
      : up < total
        ? "bg-amber-600/20 text-amber-400"
        : "bg-emerald-600/20 text-emerald-400";
  return (
    <span className={`rounded px-1.5 py-0.5 font-mono text-xs ${cls}`}>
      {up}/{total}
    </span>
  );
}

function StateBadge({ state }: { state: string }) {
  const s = (state || "").toUpperCase();
  const up = s === "INSTALLED";
  const cls = up
    ? "bg-emerald-600/20 text-emerald-400"
    : s === ""
      ? "bg-red-600/20 text-red-400"
      : "bg-amber-600/20 text-amber-400";
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs ${cls}`}>
      {up ? "up" : s === "" ? "down" : s}
    </span>
  );
}

/** Ping-monitor result badge — null when no monitor is configured (state "none"). */
export function PingBadge({ child }: { child: IPsecChild }) {
  const ps = child.ping_state;
  if (!ps || ps === "none") return null;
  const map: Record<string, { cls: string; label: string }> = {
    ok: {
      cls: "bg-emerald-600/20 text-emerald-400",
      label: child.ping_rtt_ms != null ? `ping ${child.ping_rtt_ms.toFixed(1)} ms` : "ping ok",
    },
    fail: { cls: "bg-red-600/20 text-red-400", label: "ping fail" },
    error: { cls: "bg-amber-600/20 text-amber-400", label: "ping error" },
  };
  const m = map[ps] ?? { cls: "bg-slate-700 text-slate-300", label: ps };
  const lossPart = child.ping_loss_pct != null ? ` · loss ${child.ping_loss_pct}%` : "";
  const tsPart = child.ping_ts ? ` · ${new Date(child.ping_ts).toLocaleTimeString()}` : "";
  return (
    <span
      title={`Ping ${ps}${lossPart}${tsPart}`}
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-xs ${m.cls}`}
    >
      <Activity className="h-3 w-3" />
      {m.label}
    </span>
  );
}

interface ChildListProps {
  tunnelId: string;
  entries: IPsecChild[];
  monitors: IPsecPingMonitor[];
  onConfigure: (child: IPsecChild, existing: IPsecPingMonitor | null) => void;
  // Ping monitors run a ping on the firewall — only devices we reach via an agent
  // (or a writable path) support it. Securepoint (read-only SSH) does not.
  pingSupported?: boolean;
}

/** The per-Phase-2 detail list shown when a tunnel row is expanded. */
export function Phase2ChildList({
  tunnelId,
  entries,
  monitors,
  onConfigure,
  pingSupported = true,
}: ChildListProps) {
  if (entries.length === 0) {
    return <p className="px-3 py-2 text-xs text-slate-500">No Phase 2 entries reported.</p>;
  }
  return (
    <ul className="divide-y divide-slate-800/60">
      {entries.map((ch, i) => {
        const monitor = findMonitor(monitors, tunnelId, ch);
        const selector =
          ch.local_ts || ch.remote_ts ? `${ch.local_ts || "?"} → ${ch.remote_ts || "?"}` : ch.name;
        return (
          <li
            key={`${ch.name}-${i}`}
            className="flex flex-wrap items-center gap-2 px-3 py-2 text-xs"
          >
            <span className="font-mono text-slate-300">{selector}</span>
            <StateBadge state={ch.state} />
            {isDup(ch) && (
              <span
                title="Duplicate Phase-2: more than one installed child SA for this selector, persisting across polls"
                className="inline-flex items-center gap-1 rounded bg-sky-600/20 px-1.5 py-0.5 text-sky-300"
              >
                <Copy className="h-3 w-3" />
                {ch.dup_count && ch.dup_count > 1 ? `${ch.dup_count}× ` : ""}duplicate
              </span>
            )}
            {pingSupported && <PingBadge child={ch} />}
            {pingSupported && (
              <div className="ml-auto flex items-center gap-2">
                {monitor ? (
                  <span className="font-mono text-slate-500">
                    {monitor.source || "auto"} → {monitor.destination}
                    {!monitor.enabled && " (off)"}
                  </span>
                ) : null}
                <button
                  onClick={() => onConfigure(ch, monitor)}
                  className="inline-flex items-center gap-1 rounded px-2 py-1 text-slate-400 hover:bg-slate-800"
                >
                  <Settings2 className="h-3 w-3" />
                  {monitor ? "Edit ping" : "Add ping"}
                </button>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
