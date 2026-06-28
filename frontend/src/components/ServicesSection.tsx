import { useQuery } from "@tanstack/react-query";
import { Boxes } from "lucide-react";
import { api } from "../lib/api";
import type { ServiceInfo } from "../lib/types";

/**
 * Per-service running state (agent push only). Hidden when the box reports no
 * services (e.g. direct-poll / Securepoint instances). Stopped services are
 * sorted to the top so problems are immediately visible.
 */
export default function ServicesSection({ instanceId }: { instanceId: number }) {
  const { data } = useQuery({
    queryKey: ["services", instanceId],
    queryFn: () => api.get<ServiceInfo[]>(`/api/instances/${instanceId}/services`),
    refetchInterval: 30_000,
  });

  if (!data || data.length === 0) return null;

  const sorted = [...data].sort((a, b) => {
    if (a.running !== b.running) return a.running ? 1 : -1; // stopped first
    return a.name.localeCompare(b.name);
  });
  const stopped = data.filter((s) => !s.running).length;

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <Boxes className="h-4 w-4" /> Services
        <span className="text-xs font-normal text-slate-500">
          {data.length - stopped}/{data.length} running
        </span>
      </h2>
      <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-left text-xs text-slate-500">
            <tr>
              <th className="px-3 py-2">Service</th>
              <th className="px-3 py-2">Description</th>
              <th className="px-3 py-2">State</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((s) => (
              <tr key={s.name} className="border-t border-slate-800">
                <td className="px-3 py-2 font-mono text-xs font-medium">{s.name}</td>
                <td className="px-3 py-2 text-slate-400">{s.description || "—"}</td>
                <td className="px-3 py-2">
                  <span className={s.running ? "text-emerald-400" : "text-red-400"}>
                    {s.running ? "running" : "stopped"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
