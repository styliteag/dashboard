/**
 * Tunnel state-change history, shown behind a popup on the VPN overview.
 *
 * Reads the recorded transition log for one tunnel (phase-1 up/down, phase-2
 * count changes, per-child ping ok/fail) and renders it as a newest-first
 * timeline. History is populated by the agent push, so direct-API instances
 * (or a tunnel that has never changed since rollout) show an empty state.
 */
import { useQuery } from "@tanstack/react-query";
import { Link2, Unlink, Activity, ArrowRight, Clock } from "lucide-react";
import { api } from "../lib/api";
import type { IPsecTunnelEvent } from "../lib/types";
import Dialog from "./Dialog";

interface Props {
  instanceId: number;
  tunnelId: string;
  tunnelDescription: string;
  onClose: () => void;
}

interface EventStyle {
  icon: typeof Link2;
  cls: string;
  label: string;
}

function styleFor(ev: IPsecTunnelEvent): EventStyle {
  switch (ev.event_type) {
    case "phase1_up":
      return { icon: Link2, cls: "text-emerald-400", label: "Tunnel up" };
    case "phase1_down":
      return { icon: Unlink, cls: "text-red-400", label: "Tunnel down" };
    case "phase1_changed":
      return { icon: Activity, cls: "text-slate-300", label: "Phase 1 changed" };
    case "phase2_changed":
      return { icon: Activity, cls: "text-amber-400", label: "Phase 2 changed" };
    case "ping_ok":
      return { icon: Activity, cls: "text-emerald-400", label: "Ping ok" };
    case "ping_fail":
      return { icon: Activity, cls: "text-red-400", label: "Ping fail" };
    default:
      return { icon: Activity, cls: "text-slate-400", label: ev.event_type };
  }
}

function fmtTs(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
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
        `/api/instances/${instanceId}/ipsec/${encodeURIComponent(tunnelId)}/history`,
      ),
  });

  return (
    <Dialog title={`History — ${tunnelDescription}`} onClose={onClose} wide>
      {isLoading ? (
        <p className="text-sm text-slate-500">Loading history…</p>
      ) : isError ? (
        <p className="text-sm text-red-400">Failed to load history.</p>
      ) : !data || data.length === 0 ? (
        <p className="text-sm text-slate-500">
          No recorded state changes yet. History is collected from agent pushes
          and grows as the tunnel changes state.
        </p>
      ) : (
        <ul className="max-h-[60vh] space-y-2 overflow-y-auto pr-1">
          {data.map((ev, i) => {
            const s = styleFor(ev);
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
      )}
    </Dialog>
  );
}
