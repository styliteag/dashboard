import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ScrollText, ChevronDown, ChevronUp } from "lucide-react";
import { api } from "../lib/api";

export default function FirewallLogSection({ instanceId }: { instanceId: number }) {
  const [expanded, setExpanded] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["firewall-log", instanceId],
    queryFn: () => api.get<Record<string, string>[]>(`/api/instances/${instanceId}/firewall-log?limit=30`),
    refetchInterval: 30_000,
    enabled: expanded,
  });

  return (
    <section className="mt-8">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 text-sm font-semibold text-slate-400 hover:text-slate-200"
      >
        <ScrollText className="h-4 w-4" /> Firewall Log
        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </button>

      {expanded && (
        <div className="mt-3 max-h-96 overflow-auto rounded-lg border border-slate-800">
          {isLoading ? (
            <p className="p-4 text-sm text-slate-500">Loading…</p>
          ) : !data || data.length === 0 ? (
            <p className="p-4 text-sm text-slate-500">No log entries.</p>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-slate-900 text-left text-slate-500">
                <tr>
                  <th className="px-2 py-1.5">Time</th>
                  <th className="px-2 py-1.5">Action</th>
                  <th className="px-2 py-1.5">Interface</th>
                  <th className="px-2 py-1.5">Source</th>
                  <th className="px-2 py-1.5">Destination</th>
                  <th className="px-2 py-1.5">Proto</th>
                </tr>
              </thead>
              <tbody>
                {data.map((entry, i) => (
                  <tr key={i} className="border-t border-slate-800/50">
                    <td className="whitespace-nowrap px-2 py-1 text-slate-500">
                      {entry.__timestamp__ || entry.timestamp || ""}
                    </td>
                    <td className="px-2 py-1">
                      <span className={
                        entry.action === "pass" ? "text-emerald-400" :
                        entry.action === "block" ? "text-red-400" : "text-slate-400"
                      }>
                        {entry.action || ""}
                      </span>
                    </td>
                    <td className="px-2 py-1 text-slate-400">{entry.interface || ""}</td>
                    <td className="px-2 py-1 font-mono">
                      {entry.src || entry.srcip || ""}{entry.srcport ? `:${entry.srcport}` : ""}
                    </td>
                    <td className="px-2 py-1 font-mono">
                      {entry.dst || entry.dstip || ""}{entry.dstport ? `:${entry.dstport}` : ""}
                    </td>
                    <td className="px-2 py-1 text-slate-400">{entry.protoname || entry.proto || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </section>
  );
}
