import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { api } from "../lib/api";

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

export default function ChecksSection({ instanceId }: { instanceId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ["checks", instanceId],
    queryFn: () => api.get<ServiceCheck[]>(`/api/instances/${instanceId}/checks`),
    refetchInterval: 30_000,
  });

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
      <div className="mt-3 divide-y divide-slate-800 rounded-lg border border-slate-800">
        {sorted.map((c) => {
          const st = STATE[c.state] ?? STATE[3];
          return (
            <div key={c.key} className="flex items-center gap-3 px-3 py-2 text-sm">
              <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${st.dot}`} />
              <span className={`w-12 shrink-0 text-xs font-semibold ${st.text}`}>{st.label}</span>
              <span className="shrink-0 font-mono text-xs text-slate-400">{c.key}</span>
              <span className="min-w-0 flex-1 truncate text-slate-300">{c.summary}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
