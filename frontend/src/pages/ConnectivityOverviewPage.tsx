/**
 * Global Connectivity overview — every standalone ping monitor across all
 * instances with its live state, mirroring the VPN overview. Stale rows (agent
 * silent) are muted and flagged rather than trusted.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Radio, History } from "lucide-react";
import { api } from "../lib/api";
import { useAgentModeMap } from "../lib/instances";
import { WebUiIconLink } from "../components/WebUiIconLink";
import CheckHistoryDialog from "../components/CheckHistoryDialog";
import type { GlobalConnMonitor, GlobalConnectivityResponse } from "../lib/types";

function PingPill({ m }: { m: GlobalConnMonitor }) {
  if (m.stale) {
    return <span className="text-xs text-slate-500">stale · agent silent</span>;
  }
  if (!m.enabled) return <span className="text-xs text-slate-600">disabled</span>;
  const ps = m.ping_state;
  if (ps === "ok") {
    const rtt =
      m.ping_rtt_ms != null ? `${m.ping_rtt_ms.toFixed(m.ping_rtt_ms < 10 ? 2 : 0)} ms` : "ok";
    return (
      <span
        className="rounded bg-emerald-600/20 px-2 py-0.5 text-xs text-emerald-400"
        title={m.ping_loss_pct != null ? `${m.ping_loss_pct}% loss` : undefined}
      >
        ping {rtt}
      </span>
    );
  }
  if (ps === "fail") {
    return (
      <span className="rounded bg-red-600/20 px-2 py-0.5 text-xs text-red-400">ping fail</span>
    );
  }
  if (ps === "error") {
    return (
      <span className="rounded bg-amber-600/20 px-2 py-0.5 text-xs text-amber-400">ping error</span>
    );
  }
  return <span className="text-xs text-slate-600">no data yet</span>;
}

function Kpi({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${color}`}>{value}</div>
    </div>
  );
}

export default function ConnectivityOverviewPage() {
  const navigate = useNavigate();
  const agentMode = useAgentModeMap();
  const [hist, setHist] = useState<GlobalConnMonitor | null>(null);
  const { data } = useQuery({
    queryKey: ["connectivity-overview"],
    queryFn: () => api.get<GlobalConnectivityResponse>("/api/connectivity/overview"),
    refetchInterval: 30_000,
  });

  const openInstance = (id: number) => {
    // Land on the instance's Connectivity tab (persisted tab state).
    localStorage.setItem("instance.tab", "connectivity");
    navigate(`/instances/${id}`);
  };

  const monitors = data?.monitors ?? [];

  return (
    <div>
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <Radio className="h-5 w-5 text-emerald-500" /> Connectivity
      </h1>

      {data && (
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Kpi label="Total" value={data.total} color="text-slate-100" />
          <Kpi label="OK" value={data.ok} color="text-emerald-400" />
          <Kpi label="Down" value={data.down} color="text-red-400" />
          <Kpi label="Error" value={data.error} color="text-amber-400" />
        </div>
      )}

      {monitors.length === 0 ? (
        <p className="mt-6 text-sm text-slate-500">
          No connectivity checks configured yet. Add them from the Connectivity tab on an instance.
        </p>
      ) : (
        <div className="mt-5 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Instance</th>
                <th className="px-3 py-2">Check</th>
                <th className="px-3 py-2">Source → Destination</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {monitors.map((m) => (
                <tr
                  key={`${m.instance_id}-${m.id}`}
                  onClick={() => openInstance(m.instance_id)}
                  className={`cursor-pointer border-t border-slate-800 hover:bg-slate-900/60 ${
                    m.stale ? "opacity-60" : ""
                  }`}
                >
                  <td className="px-3 py-2 font-medium text-emerald-400">
                    <span className="inline-flex items-center gap-1.5">
                      {m.instance_name}
                      <WebUiIconLink
                        instanceId={m.instance_id}
                        instanceName={m.instance_name}
                        agentMode={agentMode.get(m.instance_id) ?? false}
                      />
                    </span>
                  </td>
                  <td className="px-3 py-2">{m.name}</td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">
                    {m.source || "auto"} → {m.destination}
                  </td>
                  <td className="px-3 py-2">
                    <PingPill m={m} />
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setHist(m);
                      }}
                      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                    >
                      <History className="h-3.5 w-3.5" /> History
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {hist && (
        <CheckHistoryDialog
          instanceId={hist.instance_id}
          keyPrefix={`connectivity:${hist.id}`}
          title={`History — ${hist.instance_name} · ${hist.name}`}
          hideKeyColumn
          onClose={() => setHist(null)}
        />
      )}
    </div>
  );
}
