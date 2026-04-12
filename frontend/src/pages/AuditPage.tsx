import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileText, ChevronLeft, ChevronRight } from "lucide-react";
import { api } from "../lib/api";

interface AuditEntry {
  id: number;
  ts: string;
  user_id: number | null;
  username: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  request_id: string | null;
  result: string;
  detail: Record<string, unknown> | null;
  source_ip: string | null;
}

interface AuditPage {
  items: AuditEntry[];
  total: number;
  page: number;
  page_size: number;
}

const PAGE_SIZE = 50;

export default function AuditLogPage() {
  const [page, setPage] = useState(1);
  const [actionFilter, setActionFilter] = useState("");
  const [hoursFilter, setHoursFilter] = useState("");

  const params = new URLSearchParams();
  params.set("page", String(page));
  params.set("page_size", String(PAGE_SIZE));
  if (actionFilter) params.set("action", actionFilter);
  if (hoursFilter) params.set("hours", hoursFilter);

  const { data, isLoading } = useQuery({
    queryKey: ["audit", page, actionFilter, hoursFilter],
    queryFn: () => api.get<AuditPage>(`/api/audit?${params.toString()}`),
    refetchInterval: 30_000,
  });

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div>
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <FileText className="h-5 w-5 text-slate-400" /> Audit Log
      </h1>

      {/* Filters */}
      <div className="mt-4 flex flex-wrap gap-3">
        <div className="space-y-1">
          <label className="text-xs text-slate-500">Action</label>
          <input
            type="text"
            value={actionFilter}
            onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
            placeholder="z.B. auth, ipsec, firmware"
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs text-slate-500">Zeitraum (Stunden)</label>
          <input
            type="number"
            value={hoursFilter}
            onChange={(e) => { setHoursFilter(e.target.value); setPage(1); }}
            placeholder="24"
            min={1}
            className="w-24 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </div>
        {data && (
          <div className="flex items-end">
            <span className="rounded-lg bg-slate-800 px-3 py-1.5 text-xs text-slate-400">
              {data.total} Eintraege
            </span>
          </div>
        )}
      </div>

      {/* Table */}
      {isLoading ? (
        <p className="mt-6 text-slate-500">Laden…</p>
      ) : data && data.items.length === 0 ? (
        <p className="mt-6 text-slate-500">Keine Eintraege.</p>
      ) : data ? (
        <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Zeit</th>
                <th className="px-3 py-2">User</th>
                <th className="px-3 py-2">Action</th>
                <th className="px-3 py-2">Target</th>
                <th className="px-3 py-2">Result</th>
                <th className="px-3 py-2">IP</th>
                <th className="px-3 py-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e.id} className="border-t border-slate-800">
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-400">
                    {new Date(e.ts).toLocaleString("de-DE")}
                  </td>
                  <td className="px-3 py-2 text-xs">{e.username ?? "—"}</td>
                  <td className="px-3 py-2">
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs">
                      {e.action}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-400">
                    {e.target_type && `${e.target_type}:${e.target_id}`}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={`text-xs font-medium ${
                        e.result === "ok"
                          ? "text-emerald-400"
                          : e.result === "error"
                            ? "text-red-400"
                            : "text-amber-400"
                      }`}
                    >
                      {e.result}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-500">
                    {e.source_ip ?? "—"}
                  </td>
                  <td className="max-w-xs truncate px-3 py-2 text-xs text-slate-500">
                    {e.detail ? JSON.stringify(e.detail) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="mt-4 flex items-center justify-center gap-3">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="rounded-md p-1 text-slate-400 hover:bg-slate-800 disabled:opacity-30"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="text-sm text-slate-400">
            Seite {page} / {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="rounded-md p-1 text-slate-400 hover:bg-slate-800 disabled:opacity-30"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </div>
  );
}
