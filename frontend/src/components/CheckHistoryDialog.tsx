/**
 * Generic per-surface check-history popup. Reads the recorded check-event
 * transition log for one instance, narrowed to a single surface by `keyPrefix`
 * (e.g. "connectivity:42", "availability", "gateway:") via the backend's
 * key_prefix filter — so one component serves connectivity, availability,
 * gateways, certs, … without a bespoke dialog each. Populated by the agent-push
 * ingest (availability also by the scheduler); empty state otherwise.
 */
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { CheckHistoryEvent } from "../lib/types";
import Dialog from "./Dialog";

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

interface Props {
  instanceId: number;
  /** Restrict to one surface, e.g. `connectivity:42` or `availability`. */
  keyPrefix: string;
  title: string;
  /** Hide the per-row Check column when every row shares the same key. */
  hideKeyColumn?: boolean;
  onClose: () => void;
}

export default function CheckHistoryDialog({
  instanceId,
  keyPrefix,
  title,
  hideKeyColumn = false,
  onClose,
}: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["check-history", instanceId, keyPrefix],
    queryFn: () =>
      api.get<CheckHistoryEvent[]>(
        `/api/instances/${instanceId}/checks/history?limit=200&key_prefix=${encodeURIComponent(
          keyPrefix,
        )}`,
      ),
    refetchOnWindowFocus: false,
  });

  return (
    <Dialog title={title} onClose={onClose}>
      {isLoading ? (
        <p className="px-1 py-6 text-sm text-slate-500">Loading…</p>
      ) : !data || data.length === 0 ? (
        <p className="px-1 py-6 text-sm text-slate-500">
          No recorded transitions yet. History is captured from agent pushes (and instance
          online/offline), so a brand-new or never-changed surface shows nothing.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">When</th>
                {!hideKeyColumn && <th className="px-3 py-2">Check</th>}
                <th className="px-3 py-2">Change</th>
                <th className="px-3 py-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.map((e, i) => (
                <tr key={`${e.ts}:${e.check_key}:${i}`} className="border-t border-slate-800">
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">
                    {new Date(e.ts).toLocaleString()}
                  </td>
                  {!hideKeyColumn && <td className="px-3 py-2 font-mono text-xs">{e.check_key}</td>}
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
      )}
    </Dialog>
  );
}
