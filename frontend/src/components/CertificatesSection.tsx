import { useQuery } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import { fmtDate } from "../lib/datetime";
import type { CertInfo } from "../lib/types";

function expiryClass(days: number): string {
  if (days < 7) return "text-red-400";
  if (days < 30) return "text-amber-400";
  return "text-emerald-400";
}

function expiryLabel(days: number): string {
  if (days < 0) return `expired ${-days}d ago`;
  if (days === 0) return "expires today";
  return `${days}d left`;
}

/**
 * Certificate inventory + expiry (agent push only). Soonest expiry first; hidden
 * when the box reports no certificates (e.g. direct-poll / Securepoint).
 */
export default function CertificatesSection({ instanceId }: { instanceId: number }) {
  const { data } = useQuery({
    queryKey: ["certificates", instanceId],
    queryFn: () => api.get<CertInfo[]>(`/api/instances/${instanceId}/certificates`),
    refetchInterval: 300_000,
  });

  if (!data || data.length === 0) return null;
  const sorted = [...data].sort((a, b) => a.days_remaining - b.days_remaining);

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <ShieldCheck className="h-4 w-4" /> Certificates
      </h2>
      <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-left text-xs text-slate-500">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Type</th>
              <th className="px-3 py-2">Expires</th>
              <th className="px-3 py-2">Remaining</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((c) => (
              <tr key={`${c.type}:${c.refid || c.name}`} className="border-t border-slate-800">
                <td className="px-3 py-2 font-medium">
                  {c.name}
                  {c.is_gui && (
                    <span className="ml-2 rounded bg-sky-900/60 px-1.5 py-0.5 text-[10px] text-sky-300">
                      GUI
                    </span>
                  )}
                </td>
                <td className="px-3 py-2 text-slate-400">{c.type.toUpperCase()}</td>
                <td className="px-3 py-2 font-mono text-xs text-slate-400">
                  {fmtDate(c.not_after)}
                </td>
                <td className={`px-3 py-2 ${expiryClass(c.days_remaining)}`}>
                  {expiryLabel(c.days_remaining)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
