import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronUp, FileText, Loader2 } from "lucide-react";
import { api } from "../lib/api";
import { fmtDateTime, fmtRelative } from "../lib/datetime";

interface LogfileItem {
  id: number;
  name: string;
  collected_at: string;
  bytes: number;
}
interface LogfileContent extends LogfileItem {
  content: string;
}

function fmtBytes(n: number): string {
  return n >= 1024 ? `${(n / 1024).toFixed(0)} KB` : `${n} B`;
}

/**
 * Raw log snapshots pushed by the agent (newest few per log name). Click a
 * snapshot to load its full content from the backend.
 */
export default function LogSnapshotsSection({ instanceId }: { instanceId: number }) {
  const [expanded, setExpanded] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const { data: logs = [] } = useQuery({
    queryKey: ["instance-logs", instanceId],
    queryFn: () => api.get<LogfileItem[]>(`/api/instances/${instanceId}/logs`),
    enabled: expanded,
  });

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ["instance-log-content", instanceId, selectedId],
    queryFn: () =>
      api.get<LogfileContent>(`/api/instances/${instanceId}/logs/${selectedId}/content`),
    enabled: expanded && selectedId !== null,
  });

  return (
    <section className="mt-8">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 text-sm font-semibold text-slate-400 hover:text-slate-200"
      >
        <FileText className="h-4 w-4" /> Log Snapshots
        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </button>

      {expanded && (
        <div className="mt-3 space-y-3 rounded-lg border border-slate-800 p-4">
          {logs.length === 0 ? (
            <p className="text-sm text-slate-500">
              No log snapshots yet — the agent collects important logs hourly. They appear here once
              the next collection runs.
            </p>
          ) : (
            <>
              <div className="flex flex-wrap gap-2">
                {logs.map((l) => (
                  <button
                    key={l.id}
                    type="button"
                    onClick={() => setSelectedId(selectedId === l.id ? null : l.id)}
                    className={`rounded px-2 py-1 text-xs ${
                      selectedId === l.id
                        ? "bg-sky-700 text-white"
                        : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                    }`}
                  >
                    {l.name} ·{" "}
                    <span title={fmtDateTime(l.collected_at)}>{fmtRelative(l.collected_at)}</span> ·{" "}
                    {fmtBytes(l.bytes)}
                  </button>
                ))}
              </div>

              {selectedId !== null &&
                (detailLoading ? (
                  <p className="flex items-center gap-2 text-sm text-slate-500">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…
                  </p>
                ) : detail ? (
                  <>
                    <p className="text-xs text-slate-500">
                      {detail.name} · {fmtDateTime(detail.collected_at)} · {fmtBytes(detail.bytes)}
                    </p>
                    <pre className="max-h-96 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 text-[11px] leading-relaxed text-slate-300">
                      {detail.content}
                    </pre>
                  </>
                ) : null)}
            </>
          )}
        </div>
      )}
    </section>
  );
}
