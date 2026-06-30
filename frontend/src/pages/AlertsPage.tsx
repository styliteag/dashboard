import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Link as LinkIcon, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useAgentModeMap } from "../lib/instances";
import { WebUiIconLink } from "../components/WebUiIconLink";
import type { ServiceAlert } from "../lib/types";

const STATE: Record<number, { label: string; dot: string; text: string; row: string }> = {
  0: { label: "OK", dot: "bg-emerald-400", text: "text-emerald-400", row: "" },
  1: { label: "WARN", dot: "bg-amber-400", text: "text-amber-400", row: "bg-amber-950/30" },
  2: { label: "CRIT", dot: "bg-red-400", text: "text-red-400", row: "bg-red-950/30" },
  3: { label: "UNK", dot: "bg-slate-500", text: "text-slate-400", row: "bg-slate-900/40" },
};

export default function AlertsPage() {
  const [search, setSearch] = useState("");
  const [problemsOnly, setProblemsOnly] = useState(true);
  const [cmkFilter, setCmkFilter] = useState<"all" | "exported" | "excluded">("all");
  const agentMode = useAgentModeMap();

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["alerts"],
    queryFn: () => api.get<ServiceAlert[]>("/api/checks"),
    refetchInterval: 30_000,
  });

  const alerts = data ?? [];

  const filtered = alerts.filter((a) => {
    const matchSearch =
      !search ||
      a.instance_name.toLowerCase().includes(search.toLowerCase()) ||
      a.key.toLowerCase().includes(search.toLowerCase()) ||
      a.summary.toLowerCase().includes(search.toLowerCase());

    const matchState = !problemsOnly || a.state !== 0;

    const matchCmk =
      cmkFilter === "all" ||
      (cmkFilter === "exported" && !a.excluded) ||
      (cmkFilter === "excluded" && a.excluded);

    return matchSearch && matchState && matchCmk;
  });

  // Already sorted by backend (worst first). Keep relative order.
  const sorted = [...filtered];

  const totalCrit = alerts.filter((a) => a.state === 2).length;
  const totalWarn = alerts.filter((a) => a.state === 1).length;
  const totalOk = alerts.filter((a) => a.state === 0).length;
  const totalExcluded = alerts.filter((a) => a.excluded).length;

  return (
    <div>
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <AlertTriangle className="h-5 w-5 text-amber-400" /> Alerts
        </h1>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm hover:bg-slate-700"
          disabled={isFetching}
        >
          Refresh
        </button>
      </div>

      <p className="mt-1 text-sm text-slate-400">
        Live service checks. The Checkmk column shows whether each is exported — export is opt-in,
        picked in Settings → Checkmk; the dashboard always shows everything.
      </p>

      {/* Summary */}
      <div className="mt-4 flex flex-wrap gap-2 text-sm">
        {totalCrit > 0 && (
          <span className="rounded bg-red-900/30 px-2 py-0.5 text-red-400">{totalCrit} CRIT</span>
        )}
        {totalWarn > 0 && (
          <span className="rounded bg-amber-900/30 px-2 py-0.5 text-amber-400">
            {totalWarn} WARN
          </span>
        )}
        <span className="rounded bg-emerald-900/30 px-2 py-0.5 text-emerald-400">{totalOk} OK</span>
        {totalExcluded > 0 && (
          <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-400">
            {totalExcluded} not exported to Checkmk
          </span>
        )}
      </div>

      {/* Filters */}
      <div className="mt-4 flex flex-wrap items-end gap-3">
        <div className="relative min-w-[220px] flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search instance, check key, or summary…"
            className="w-full rounded-lg border border-slate-700 bg-slate-800 py-2 pl-9 pr-3 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </div>

        <label className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-sm">
          <input
            type="checkbox"
            checked={problemsOnly}
            onChange={(e) => setProblemsOnly(e.target.checked)}
            className="accent-emerald-600"
          />
          Problems only
        </label>

        <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 p-1 text-sm">
          <span className="px-2 text-xs text-slate-500">Checkmk</span>
          {(
            [
              { v: "all", label: "All" },
              { v: "exported", label: "Exported" },
              { v: "excluded", label: "Excluded" },
            ] as const
          ).map((opt) => (
            <button
              key={opt.v}
              onClick={() => setCmkFilter(opt.v)}
              className={`rounded px-2 py-1 text-xs ${
                cmkFilter === opt.v
                  ? "bg-emerald-600 text-white"
                  : "text-slate-300 hover:bg-slate-800"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      {isLoading ? (
        <p className="mt-6 text-slate-500">Loading checks…</p>
      ) : sorted.length === 0 ? (
        <p className="mt-6 text-slate-400">
          {alerts.length === 0 ? "No instances or checks." : "No matching checks."}
        </p>
      ) : (
        <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">State</th>
                <th className="px-3 py-2">Instance</th>
                <th className="px-3 py-2">Check</th>
                <th className="px-3 py-2">Summary</th>
                <th className="px-3 py-2">Checkmk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {sorted.map((a) => {
                const st = STATE[a.state] ?? STATE[3];
                return (
                  <tr key={`${a.instance_id}:${a.key}`} className={st.row}>
                    <td className="px-3 py-2">
                      <span className="inline-flex items-center gap-1.5">
                        <span className={`inline-block h-2 w-2 rounded-full ${st.dot}`} />
                        <span className={`text-xs font-semibold ${st.text}`}>{st.label}</span>
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className="inline-flex items-center gap-1.5">
                        <Link
                          to={`/instances/${a.instance_id}`}
                          className="inline-flex items-center gap-1 text-emerald-400 hover:underline"
                        >
                          {a.instance_name}
                          <LinkIcon className="h-3 w-3" />
                        </Link>
                        <WebUiIconLink
                          instanceId={a.instance_id}
                          instanceName={a.instance_name}
                          agentMode={agentMode.get(a.instance_id) ?? false}
                        />
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-400">{a.key}</td>
                    <td className="px-3 py-2 text-slate-300">{a.summary}</td>
                    <td className="px-3 py-2">
                      {a.excluded ? (
                        <span className="text-xs text-slate-500" title={a.excluded_by ?? ""}>
                          excluded {a.excluded_by ? `(${a.excluded_by})` : ""}
                        </span>
                      ) : (
                        <span className="text-xs text-emerald-500">exported</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-3 text-xs text-slate-500">
        {sorted.length} shown · {alerts.length} total checks · updates every 30s
      </p>
    </div>
  );
}
