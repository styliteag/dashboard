import { useQuery } from "@tanstack/react-query";
import { FileClock } from "lucide-react";
import { api } from "../lib/api";
import { fmtDateTime, fmtRelative } from "../lib/datetime";
import type { ConfigInfoResponse } from "../lib/types";

function fmtWhen(iso: string | null): { abs: string; ago: string } | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return { abs: fmtDateTime(d), ago: fmtRelative(d) };
}

/**
 * Configuration status: when config.xml was last changed (and by whom — from the
 * agent's <revision>) and when a config backup was last downloaded through the
 * dashboard (from the audit log). Hidden when neither is known.
 */
export default function ConfigSection({ instanceId }: { instanceId: number }) {
  const { data } = useQuery({
    queryKey: ["config-info", instanceId],
    queryFn: () => api.get<ConfigInfoResponse>(`/api/instances/${instanceId}/config-info`),
    refetchInterval: 60_000,
  });

  if (!data) return null;
  const changed = fmtWhen(data.revision_time || null);
  const backup = fmtWhen(data.last_backup_at);
  if (!changed && !backup) return null;

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <FileClock className="h-4 w-4" /> Configuration
      </h2>
      <div className="mt-3 grid gap-4 sm:grid-cols-2">
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-3">
          <div className="text-xs text-slate-500">Last change</div>
          {changed ? (
            <>
              <div className="mt-1 text-sm">
                {changed.abs} <span className="text-slate-500">· {changed.ago}</span>
              </div>
              <div className="mt-0.5 text-xs text-slate-400">
                {data.revision_user || "unknown"}
                {data.revision_description ? ` — ${data.revision_description}` : ""}
              </div>
            </>
          ) : (
            <div className="mt-1 text-sm text-slate-500">unknown</div>
          )}
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-3">
          <div className="text-xs text-slate-500">Last backup downloaded</div>
          {backup ? (
            <div className="mt-1 text-sm">
              {backup.abs} <span className="text-slate-500">· {backup.ago}</span>
            </div>
          ) : (
            <div className="mt-1 text-sm text-amber-400">never</div>
          )}
        </div>
      </div>
    </section>
  );
}
