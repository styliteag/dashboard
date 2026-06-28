import { useQuery } from "@tanstack/react-query";
import { Activity, ArrowLeftRight, Clock4, Gauge } from "lucide-react";
import { api } from "../lib/api";
import type { SystemStatus } from "../lib/types";

/**
 * Compact system-health row: load average, swap, pf state-table fill, and NTP
 * sync. All four come from the agent push; direct-poll instances report no data
 * (load all-zero, swap_total_mb 0, pf states_limit 0, ntp stratum -1) and the
 * respective card is hidden. Renders nothing when none are available.
 */
export default function SystemHealthSection({ instanceId }: { instanceId: number }) {
  const { data } = useQuery({
    queryKey: ["status", instanceId],
    queryFn: () => api.get<SystemStatus>(`/api/instances/${instanceId}/status`),
    refetchInterval: 30_000,
  });

  if (!data) return null;

  const hasLoad = data.load && (data.load.one > 0 || data.load.five > 0 || data.load.fifteen > 0);
  const hasSwap = data.memory.swap_total_mb > 0;
  const hasPf = data.pf && data.pf.states_limit > 0;
  const hasNtp = data.ntp && data.ntp.stratum >= 0;
  if (!hasLoad && !hasSwap && !hasPf && !hasNtp) return null;

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <Activity className="h-4 w-4" /> System
      </h2>
      <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {hasLoad && (
          <Card icon={<Gauge className="h-4 w-4 text-emerald-400" />} label="Load avg">
            <span className="font-mono">
              {data.load.one.toFixed(2)} · {data.load.five.toFixed(2)} ·{" "}
              {data.load.fifteen.toFixed(2)}
            </span>
            <span className="ml-1 text-xs text-slate-500">1·5·15m</span>
          </Card>
        )}
        {hasSwap && (
          <Card icon={<ArrowLeftRight className="h-4 w-4 text-indigo-400" />} label="Swap">
            <span className={data.memory.swap_used_pct >= 50 ? "text-amber-400" : ""}>
              {data.memory.swap_used_pct.toFixed(1)}%
            </span>
            <span className="ml-1 text-xs text-slate-500">
              {data.memory.swap_used_mb.toFixed(0)} / {data.memory.swap_total_mb.toFixed(0)} MB
            </span>
          </Card>
        )}
        {hasPf && (
          <Card icon={<Activity className="h-4 w-4 text-sky-400" />} label="pf states">
            <span className={data.pf.states_pct >= 80 ? "text-amber-400" : ""}>
              {data.pf.states_current.toLocaleString()}
            </span>
            <span className="ml-1 text-xs text-slate-500">
              / {data.pf.states_limit.toLocaleString()} ({data.pf.states_pct.toFixed(1)}%)
            </span>
          </Card>
        )}
        {hasNtp && (
          <Card icon={<Clock4 className="h-4 w-4 text-amber-400" />} label="NTP">
            {data.ntp.synced ? (
              <span className="text-emerald-400">synced</span>
            ) : (
              <span className="text-amber-400">not synced</span>
            )}
            <span className="ml-1 text-xs text-slate-500">
              {data.ntp.synced
                ? `stratum ${data.ntp.stratum}, ${data.ntp.offset_ms.toFixed(1)}ms${
                    data.ntp.peer ? ` · ${data.ntp.peer}` : ""
                  }`
                : "no usable peer"}
            </span>
          </Card>
        )}
      </div>
    </section>
  );
}

function Card({
  icon,
  label,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-3">
      <div className="flex items-center gap-2 text-xs text-slate-500">
        {icon} {label}
      </div>
      <div className="mt-1 text-sm">{children}</div>
    </div>
  );
}
