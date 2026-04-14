import { useQuery } from "@tanstack/react-query";
import { Globe } from "lucide-react";
import { api } from "../lib/api";

interface GatewayStatus {
  name: string;
  address: string;
  status: string;
  delay: string;
  stddev: string;
  loss: string;
  interface: string;
}

export default function GatewaySection({ instanceId }: { instanceId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ["gateways", instanceId],
    queryFn: () => api.get<GatewayStatus[]>(`/api/instances/${instanceId}/gateways`),
    refetchInterval: 30_000,
  });

  if (isLoading) return null;
  if (!data || data.length === 0) return null;

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <Globe className="h-4 w-4" /> Gateways
      </h2>
      <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-left text-xs text-slate-500">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Gateway</th>
              <th className="px-3 py-2">Interface</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Delay</th>
              <th className="px-3 py-2">Loss</th>
            </tr>
          </thead>
          <tbody>
            {data.map((gw) => {
              const isUp = !gw.status || gw.status.toLowerCase() === "none" || gw.status.toLowerCase().includes("online");
              return (
                <tr key={gw.name} className="border-t border-slate-800">
                  <td className="px-3 py-2 font-medium">{gw.name}</td>
                  <td className="px-3 py-2 font-mono text-xs">{gw.address}</td>
                  <td className="px-3 py-2 text-slate-400">{gw.interface}</td>
                  <td className="px-3 py-2">
                    <span className={isUp ? "text-emerald-400" : "text-red-400"}>
                      {isUp ? "online" : gw.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{gw.delay || "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs">{gw.loss || "—"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
