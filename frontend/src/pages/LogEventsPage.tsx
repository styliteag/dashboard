import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { api } from "../lib/api";
import { fmtDateTime, fmtRelative } from "../lib/datetime";

interface LogEventItem {
  instance_id: number;
  instance_name: string;
  log_name: string;
  severity: number;
  program: string;
  pattern: string;
  sample: string;
  count: number;
  last_ts: string;
  updated_at: string;
}

const LEVELS = [
  { max: 2, label: "Critical" },
  { max: 3, label: "Errors" },
  { max: 4, label: "Warnings" },
] as const;

const SEV_LABEL: Record<number, string> = {
  0: "emerg",
  1: "alert",
  2: "crit",
  3: "error",
  4: "warn",
};

function sevClass(sev: number): string {
  if (sev <= 2) return "bg-red-900/60 text-red-300";
  if (sev === 3) return "bg-orange-900/60 text-orange-300";
  return "bg-yellow-900/50 text-yellow-300";
}

/**
 * Global view of aggregated critical log events across all (visible) instances.
 * Events come pre-filtered and pre-aggregated from the backend (one row per
 * normalized message pattern, with a count over the current snapshot window).
 */
export default function LogEventsPage() {
  const [maxSeverity, setMaxSeverity] = useState<number>(3);
  const [instanceFilter, setInstanceFilter] = useState("");

  const { data: events = [], isLoading } = useQuery({
    queryKey: ["log-events", maxSeverity],
    queryFn: () => api.get<LogEventItem[]>(`/api/logs/events?max_severity=${maxSeverity}`),
    refetchInterval: 60_000,
  });

  const filter = instanceFilter.trim().toLowerCase();
  const visible = filter
    ? events.filter((e) => e.instance_name.toLowerCase().includes(filter))
    : events;

  return (
    <div className="mx-auto max-w-7xl px-6 py-6">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <ScrollText className="h-5 w-5 text-emerald-500" /> Log Events
        </h1>
        <div className="flex rounded-lg border border-slate-700 text-sm">
          {LEVELS.map((lvl) => (
            <button
              key={lvl.max}
              type="button"
              onClick={() => setMaxSeverity(lvl.max)}
              className={`px-3 py-1.5 first:rounded-l-lg last:rounded-r-lg ${
                maxSeverity === lvl.max
                  ? "bg-slate-700 text-slate-100"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {lvl.label}
            </button>
          ))}
        </div>
        <input
          value={instanceFilter}
          onChange={(e) => setInstanceFilter(e.target.value)}
          placeholder="Filter by instance…"
          className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-100 placeholder:text-slate-500"
        />
        <span className="text-xs text-slate-500">
          {visible.length} pattern{visible.length === 1 ? "" : "s"}
        </span>
      </div>

      <p className="mb-4 text-xs text-slate-500">
        Aggregated from the agents’ hourly log snapshots: one row per message pattern (IPs and
        numbers masked), counted over the newest snapshot per log. Known steady-state noise is
        filtered out.
      </p>

      {isLoading ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : visible.length === 0 ? (
        <p className="text-sm text-slate-500">
          No log events at this level — try a broader level above.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-xs">
            <thead className="bg-slate-900 text-left text-slate-500">
              <tr>
                <th className="px-2 py-1.5">Severity</th>
                <th className="px-2 py-1.5">Instance</th>
                <th className="px-2 py-1.5">Log</th>
                <th className="px-2 py-1.5">Program</th>
                <th className="px-2 py-1.5">Message pattern</th>
                <th className="px-2 py-1.5 text-right">Count</th>
                <th className="px-2 py-1.5">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((e, i) => (
                <tr key={i} className="border-t border-slate-800/50 align-top">
                  <td className="px-2 py-1.5">
                    <span className={`rounded px-1.5 py-0.5 font-medium ${sevClass(e.severity)}`}>
                      {SEV_LABEL[e.severity] ?? e.severity}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5">
                    <Link
                      to={`/instances/${e.instance_id}`}
                      className="text-sky-400 hover:text-sky-300"
                    >
                      {e.instance_name}
                    </Link>
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-slate-400">{e.log_name}</td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-slate-400">{e.program}</td>
                  <td className="px-2 py-1.5 font-mono text-slate-300" title={e.sample}>
                    {e.pattern}
                  </td>
                  <td className="px-2 py-1.5 text-right text-slate-400">{e.count}</td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-slate-500">
                    <span title={`${e.last_ts} · updated ${fmtDateTime(e.updated_at)}`}>
                      {fmtRelative(e.updated_at)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
