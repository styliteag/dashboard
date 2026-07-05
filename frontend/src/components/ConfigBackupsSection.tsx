import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download, History, Loader2 } from "lucide-react";
import { api } from "../lib/api";
import { fmtDateTime, fmtRelative } from "../lib/datetime";
import type { ConfigBackupDiff, ConfigBackupItem } from "../lib/types";

function fmtBytes(n: number): string {
  return n >= 1024 ? `${(n / 1024).toFixed(0)} KB` : `${n} B`;
}

function diffLineClass(line: string): string {
  if (line.startsWith("+++") || line.startsWith("---")) return "text-slate-500";
  if (line.startsWith("@@")) return "text-sky-400";
  if (line.startsWith("+")) return "text-emerald-400";
  if (line.startsWith("-")) return "text-rose-400";
  return "text-slate-300";
}

/**
 * Versioned config.xml backups (agent pushes a new version whenever the file
 * changes). Pick two versions to see what changed between them; every version
 * can be downloaded for disaster recovery.
 *
 * When rendered under its own "Config" tab, starts expanded so the list + diff
 * viewer are immediately visible.
 */
export default function ConfigBackupsSection({ instanceId }: { instanceId: number }) {
  const [selected, setSelected] = useState<number[]>([]);

  const { data: versions = [] } = useQuery({
    queryKey: ["config-backups", instanceId],
    queryFn: () => api.get<ConfigBackupItem[]>(`/api/instances/${instanceId}/config-backups`),
    refetchInterval: 60_000,
  });

  // Versions arrive newest-first; diff always runs older -> newer regardless of
  // the order the user clicked the two rows in.
  const pair =
    selected.length === 2
      ? [...selected].sort((a, b) => {
          const pos = (id: number) => versions.findIndex((v) => v.id === id);
          return pos(b) - pos(a);
        })
      : null;

  const { data: diff, isLoading: diffLoading } = useQuery({
    queryKey: ["config-backup-diff", instanceId, pair?.[0], pair?.[1]],
    queryFn: () =>
      api.get<ConfigBackupDiff>(
        `/api/instances/${instanceId}/config-backups/diff?from_id=${pair?.[0]}&to_id=${pair?.[1]}`,
      ),
    enabled: pair !== null,
  });

  const toggle = (id: number) =>
    setSelected((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur.slice(-1), id]));

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <History className="h-4 w-4" /> Config Backups
      </h2>

      <div className="mt-3 space-y-3 rounded-lg border border-slate-800 p-4">
        {versions.length === 0 ? (
          <p className="text-sm text-slate-500">
            No stored config versions yet — the agent (2.7.15+) pushes config.xml whenever it
            changes. The first version appears with its next push.
          </p>
        ) : (
          <>
            <p className="text-xs text-slate-500">
              Select two versions to compare — every real config change creates one version.
            </p>
            <ul className="divide-y divide-slate-800/60">
              {versions.map((v) => (
                <li key={v.id} className="flex items-center gap-3 py-1.5 text-sm">
                  <input
                    type="checkbox"
                    checked={selected.includes(v.id)}
                    onChange={() => toggle(v.id)}
                    className="accent-emerald-600"
                    aria-label={`select version ${v.id}`}
                  />
                  <span title={fmtDateTime(v.collected_at)} className="w-40 shrink-0">
                    {fmtDateTime(v.collected_at)}
                  </span>
                  <span className="w-20 shrink-0 text-slate-400">
                    {fmtRelative(v.collected_at)}
                  </span>
                  <span className="w-16 shrink-0 text-right text-slate-400">
                    {fmtBytes(v.bytes)}
                  </span>
                  <span className="hidden font-mono text-xs text-slate-500 sm:inline">
                    {v.sha256.slice(0, 12)}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      window.open(
                        `/api/instances/${instanceId}/config-backups/${v.id}/download`,
                        "_blank",
                      )
                    }
                    className="ml-auto flex items-center gap-1 rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700"
                    title="Download this version (config.xml)"
                  >
                    <Download className="h-3 w-3" /> Download
                  </button>
                </li>
              ))}
            </ul>

            {pair !== null &&
              (diffLoading ? (
                <p className="flex items-center gap-2 text-sm text-slate-500">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Computing diff…
                </p>
              ) : diff ? (
                <>
                  <p className="text-xs text-slate-500">
                    {fmtDateTime(diff.from_collected_at)} → {fmtDateTime(diff.to_collected_at)}
                    {diff.truncated && <span className="ml-2 text-amber-400">diff truncated</span>}
                  </p>
                  {diff.diff === "" ? (
                    <p className="text-sm text-slate-500">No differences.</p>
                  ) : (
                    <pre className="max-h-96 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 text-[11px] leading-relaxed">
                      {diff.diff.split("\n").map((line, i) => (
                        <div key={i} className={diffLineClass(line)}>
                          {line || " "}
                        </div>
                      ))}
                    </pre>
                  )}
                </>
              ) : null)}
          </>
        )}
      </div>
    </section>
  );
}
