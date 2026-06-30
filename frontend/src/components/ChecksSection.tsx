import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { api } from "../lib/api";
import { hasInstanceRule, resolveClient, SELECTION_CONSUMERS } from "../lib/selection";
import type { SelectionConfig, SelectionRule } from "../lib/types";

interface PerfMetric {
  name: string;
  value: number;
  warn: number | null;
  crit: number | null;
  unit: string;
}

interface ServiceCheck {
  key: string;
  state: number; // 0 OK, 1 WARN, 2 CRIT, 3 UNKNOWN
  summary: string;
  metrics: PerfMetric[];
}

const STATE: Record<number, { label: string; dot: string; text: string }> = {
  0: { label: "OK", dot: "bg-emerald-400", text: "text-emerald-400" },
  1: { label: "WARN", dot: "bg-amber-400", text: "text-amber-400" },
  2: { label: "CRIT", dot: "bg-red-400", text: "text-red-400" },
  3: { label: "UNK", dot: "bg-slate-500", text: "text-slate-400" },
};

// Severity order for sorting (worst first): CRIT > WARN > UNKNOWN > OK.
const sev = (s: number) => (s === 2 ? 3 : s === 1 ? 2 : s === 3 ? 1 : 0);

// Per-instance selection state across all four consumers (the same rules the
// Settings tree edits — shared react-query cache key). Lets each check row toggle
// notifications/export for itself on this one box.
function useInstanceSelection(instanceId: number) {
  const qc = useQueryClient();
  const results = useQueries({
    queries: SELECTION_CONSUMERS.map((c) => ({
      queryKey: ["selection-config", c.key],
      queryFn: () => api.get<SelectionConfig>(`/api/selection/${c.key}/config`),
    })),
  });
  const rulesByConsumer: Record<string, SelectionRule[]> = {};
  SELECTION_CONSUMERS.forEach((c, i) => {
    rulesByConsumer[c.key] = results[i].data?.rules ?? [];
  });

  const invalidate = (consumer: string) =>
    qc.invalidateQueries({ queryKey: ["selection-config", consumer] });

  const addMut = useMutation({
    mutationFn: (v: { consumer: string; key: string; mode: "include" | "exclude" }) =>
      api.post(`/api/selection/${v.consumer}/rules`, {
        instance_id: instanceId,
        selector: v.key,
        mode: v.mode,
      }),
    onSuccess: (_d, v) => invalidate(v.consumer),
  });
  const removeMut = useMutation({
    mutationFn: (v: { consumer: string; key: string }) =>
      api.del(
        `/api/selection/${v.consumer}/rules?selector=${encodeURIComponent(v.key)}&instance_id=${instanceId}`,
      ),
    onSuccess: (_d, v) => invalidate(v.consumer),
  });

  const stateOf = (consumer: string, key: string): boolean =>
    resolveClient(key, instanceId, rulesByConsumer[consumer] ?? []).on;

  // Toggle this box's choice for one (consumer, service): clear an explicit
  // box-level rule back to inherit, else write one opposite to the effective
  // value (on→exclude to mute, off→include to add).
  const toggle = (consumer: string, key: string) => {
    if (hasInstanceRule(key, instanceId, rulesByConsumer[consumer] ?? []))
      removeMut.mutate({ consumer, key });
    else addMut.mutate({ consumer, key, mode: stateOf(consumer, key) ? "exclude" : "include" });
  };

  return { stateOf, toggle, pending: addMut.isPending || removeMut.isPending };
}

export default function ChecksSection({ instanceId }: { instanceId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ["checks", instanceId],
    queryFn: () => api.get<ServiceCheck[]>(`/api/instances/${instanceId}/checks`),
    refetchInterval: 30_000,
  });
  const sel = useInstanceSelection(instanceId);

  if (isLoading) return null;
  if (!data || data.length === 0) return null;

  const crit = data.filter((c) => c.state === 2).length;
  const warn = data.filter((c) => c.state === 1).length;
  const ok = data.filter((c) => c.state === 0).length;
  const sorted = [...data].sort((a, b) => sev(b.state) - sev(a.state));

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <Activity className="h-4 w-4" /> Service Checks
        <span className="ml-1 flex gap-2 text-xs">
          {crit > 0 && <span className="text-red-400">{crit} CRIT</span>}
          {warn > 0 && <span className="text-amber-400">{warn} WARN</span>}
          <span className="text-emerald-400">{ok} OK</span>
        </span>
      </h2>
      <p className="mt-1 text-xs text-slate-500">
        Per-service notify/export for this instance — a box-level choice overrides the global
        defaults in Settings.
      </p>

      {/* Column header: which consumer each checkbox controls. */}
      <div className="mt-3 flex items-center gap-3 px-3 text-[10px] font-semibold uppercase tracking-wide text-slate-500">
        <span className="min-w-0 flex-1" />
        {SELECTION_CONSUMERS.map((c) => (
          <span key={c.key} className="w-12 shrink-0 text-center" title={c.label}>
            {c.short}
          </span>
        ))}
      </div>

      <div className="mt-1 divide-y divide-slate-800 rounded-lg border border-slate-800">
        {sorted.map((c) => {
          const st = STATE[c.state] ?? STATE[3];
          return (
            <div key={c.key} className="flex items-center gap-3 px-3 py-2 text-sm">
              <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${st.dot}`} />
              <span className={`w-12 shrink-0 text-xs font-semibold ${st.text}`}>{st.label}</span>
              <span className="shrink-0 font-mono text-xs text-slate-400">{c.key}</span>
              <span className="min-w-0 flex-1 truncate text-slate-300">{c.summary}</span>
              {SELECTION_CONSUMERS.map((cons) => {
                const on = sel.stateOf(cons.key, c.key);
                return (
                  <span key={cons.key} className="flex w-12 shrink-0 justify-center">
                    <input
                      type="checkbox"
                      checked={on}
                      disabled={sel.pending}
                      onChange={() => sel.toggle(cons.key, c.key)}
                      title={`${cons.label}: ${on ? "on" : "off"} for ${c.key} on this instance`}
                      className="h-4 w-4 cursor-pointer accent-emerald-600 disabled:cursor-not-allowed"
                    />
                  </span>
                );
              })}
            </div>
          );
        })}
      </div>
    </section>
  );
}
