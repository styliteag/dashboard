import { useQuery } from "@tanstack/react-query";
import { History } from "lucide-react";
import { api } from "../lib/api";
import { fmtDateTime, fmtRelative } from "../lib/datetime";
import type { CheckHistoryEvent } from "../lib/types";

const STATE_LABEL: Record<number, string> = { 0: "OK", 1: "WARN", 2: "CRIT", 3: "UNK" };
const STATE_CLASS: Record<number, string> = {
  0: "text-emerald-400",
  1: "text-amber-400",
  2: "text-red-400",
  3: "text-slate-400",
};

function StateBadge({ state }: { state: number }) {
  return (
    <span className={STATE_CLASS[state] ?? "text-slate-400"}>{STATE_LABEL[state] ?? state}</span>
  );
}

/**
 * Recent service-check state transitions (alert history), most recent first.
 * Populated by the agent-push ingest; hidden when there is no history yet.
 */
export default function CheckHistorySection({ instanceId }: { instanceId: number }) {
  const { data } = useQuery({
    queryKey: ["check-history", instanceId],
    queryFn: () =>
      api.get<CheckHistoryEvent[]>(`/api/instances/${instanceId}/checks/history?limit=50`),
    refetchInterval: 30_000,
  });

  if (!data || data.length === 0) return null;

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <History className="h-4 w-4" /> Check history
      </h2>
      <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-left text-xs text-slate-500">
            <tr>
              <th className="px-3 py-2">When</th>
              <th className="px-3 py-2">Check</th>
              <th className="px-3 py-2">Change</th>
              <th className="px-3 py-2">Detail</th>
            </tr>
          </thead>
          <tbody>
            {data.map((e, i) => (
              <tr key={`${e.ts}:${e.check_key}:${i}`} className="border-t border-slate-800">
                <td
                  className="px-3 py-2 font-mono text-xs text-slate-400"
                  title={fmtDateTime(e.ts)}
                >
                  {fmtRelative(e.ts)}
                </td>
                <td className="px-3 py-2 font-mono text-xs">{e.check_key}</td>
                <td className="px-3 py-2 text-xs">
                  <StateBadge state={e.old_state} /> <span className="text-slate-600">→</span>{" "}
                  <StateBadge state={e.new_state} />
                </td>
                <td className="px-3 py-2 text-xs text-slate-400">{e.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
