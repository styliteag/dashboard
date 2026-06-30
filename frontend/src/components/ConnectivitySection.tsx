/**
 * Per-instance Connectivity tab: standalone source→destination ping monitors the
 * agent runs on the firewall. Agent-mode only (the firewall does the pinging).
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Radio, Plus, Pencil, History } from "lucide-react";
import { api } from "../lib/api";
import type { ConnectivityState } from "../lib/types";
import ConnectivityMonitorDialog from "./ConnectivityMonitorDialog";
import CheckHistoryDialog from "./CheckHistoryDialog";

function PingPill({ m }: { m: ConnectivityState }) {
  const ps = m.ping_state;
  if (ps === "ok") {
    const rtt =
      m.ping_rtt_ms != null ? `${m.ping_rtt_ms.toFixed(m.ping_rtt_ms < 10 ? 2 : 0)} ms` : "ok";
    return (
      <span
        className="rounded bg-emerald-600/20 px-2 py-0.5 text-xs text-emerald-400"
        title={
          m.ping_loss_pct != null ? `${m.ping_loss_pct}% loss · ${m.ping_ts ?? ""}` : undefined
        }
      >
        ping {rtt}
      </span>
    );
  }
  if (ps === "fail") {
    return (
      <span
        className="rounded bg-red-600/20 px-2 py-0.5 text-xs text-red-400"
        title={m.ping_ts ?? undefined}
      >
        ping fail
      </span>
    );
  }
  if (ps === "error") {
    return (
      <span className="rounded bg-amber-600/20 px-2 py-0.5 text-xs text-amber-400">ping error</span>
    );
  }
  return <span className="text-xs text-slate-600">— no data yet</span>;
}

export default function ConnectivitySection({
  instanceId,
  pingSupported,
}: {
  instanceId: number;
  pingSupported: boolean;
}) {
  const [dialog, setDialog] = useState<{ existing: ConnectivityState | null } | null>(null);
  const [hist, setHist] = useState<ConnectivityState | null>(null);

  const { data } = useQuery({
    queryKey: ["connectivity-status", instanceId],
    queryFn: () => api.get<ConnectivityState[]>(`/api/instances/${instanceId}/connectivity/status`),
    refetchInterval: 30_000,
    enabled: pingSupported,
  });

  if (!pingSupported) {
    return (
      <section className="mt-8">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
          <Radio className="h-4 w-4" /> Connectivity
        </h2>
        <p className="mt-3 text-sm text-slate-500">
          Connectivity checks run on the firewall via the agent — available in agent (push) mode
          only.
        </p>
      </section>
    );
  }

  const monitors = data ?? [];

  return (
    <section className="mt-8">
      <div className="flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
          <Radio className="h-4 w-4" /> Connectivity
        </h2>
        <button
          onClick={() => setDialog({ existing: null })}
          className="inline-flex items-center gap-1 rounded border border-slate-700 px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-800"
        >
          <Plus className="h-3.5 w-3.5" /> Add check
        </button>
      </div>

      {monitors.length === 0 ? (
        <p className="mt-3 text-sm text-slate-500">
          No connectivity checks yet. Add a source → destination ping to monitor reachability
          independent of any tunnel.
        </p>
      ) : (
        <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Source → Destination</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {monitors.map((m) => (
                <tr key={m.id} className="border-t border-slate-800">
                  <td className="px-3 py-2 font-medium">
                    {m.name}
                    {!m.enabled && <span className="ml-2 text-xs text-slate-500">(disabled)</span>}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">
                    {m.source || "auto"} → {m.destination}
                  </td>
                  <td className="px-3 py-2">
                    {m.enabled ? (
                      <PingPill m={m} />
                    ) : (
                      <span className="text-xs text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={() => setHist(m)}
                      className="mr-1 inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                    >
                      <History className="h-3.5 w-3.5" /> History
                    </button>
                    <button
                      onClick={() => setDialog({ existing: m })}
                      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                    >
                      <Pencil className="h-3.5 w-3.5" /> Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {dialog && (
        <ConnectivityMonitorDialog
          instanceId={instanceId}
          existing={dialog.existing}
          onClose={() => setDialog(null)}
        />
      )}

      {hist && (
        <CheckHistoryDialog
          instanceId={instanceId}
          keyPrefix={`connectivity:${hist.id}`}
          title={`History — ${hist.name}`}
          hideKeyColumn
          onClose={() => setHist(null)}
        />
      )}
    </section>
  );
}
