import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Package, AlertTriangle, CheckCircle, HelpCircle, Search } from "lucide-react";
import { api } from "../lib/api";

interface FirmwareEntry {
  instance_id: number;
  instance_name: string;
  location: string | null;
  product_version: string;
  product_latest: string;
  upgrade_available: boolean;
  updates_available: number;
  status_msg: string;
  needs_reboot: boolean;
  last_check: string;
}

interface FirmwareComplianceResponse {
  instances: FirmwareEntry[];
  total: number;
  up_to_date: number;
  outdated: number;
  unknown: number;
}

export default function FirmwareCompliancePage() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "outdated" | "current" | "unknown">("all");

  const { data, isLoading } = useQuery({
    queryKey: ["firmware-compliance"],
    queryFn: () => api.get<FirmwareComplianceResponse>("/api/firmware/compliance"),
    refetchInterval: 300_000,
  });

  const filtered = (data?.instances ?? []).filter((e) => {
    const matchSearch =
      e.instance_name.toLowerCase().includes(search.toLowerCase()) ||
      (e.location ?? "").toLowerCase().includes(search.toLowerCase());
    const matchFilter =
      filter === "all" ||
      (filter === "outdated" && e.upgrade_available) ||
      (filter === "current" && !e.upgrade_available && e.product_version !== "?") ||
      (filter === "unknown" && e.product_version === "?");
    return matchSearch && matchFilter;
  });

  return (
    <div>
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <Package className="h-5 w-5 text-slate-400" /> Firmware-Compliance
      </h1>

      {data && (
        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          <KpiTile label="Total" value={data.total} color="text-slate-100" />
          <KpiTile label="Aktuell" value={data.up_to_date} color="text-emerald-400" />
          <KpiTile label="Veraltet" value={data.outdated} color="text-amber-400" />
          <KpiTile label="Unbekannt" value={data.unknown} color="text-slate-500" />
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Suche…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 py-2 pl-9 pr-3 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </div>
        {(["all", "outdated", "current", "unknown"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`rounded-md px-3 py-1.5 text-xs ${
              filter === f ? "bg-emerald-600 text-white" : "text-slate-400 hover:bg-slate-800"
            }`}
          >
            {{ all: "Alle", outdated: "Veraltet", current: "Aktuell", unknown: "Unbekannt" }[f]}
          </button>
        ))}
      </div>

      {isLoading ? (
        <p className="mt-6 text-slate-500">Lade Firmware-Status aller Instanzen…</p>
      ) : (
        <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Instanz</th>
                <th className="px-3 py-2">Standort</th>
                <th className="px-3 py-2">Installiert</th>
                <th className="px-3 py-2">Neueste</th>
                <th className="px-3 py-2">Updates</th>
                <th className="px-3 py-2">Letzter Check</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.instance_id} className="border-t border-slate-800">
                  <td className="px-3 py-2">
                    {e.product_version === "?" ? (
                      <HelpCircle className="h-4 w-4 text-slate-500" />
                    ) : e.upgrade_available ? (
                      <AlertTriangle className="h-4 w-4 text-amber-400" />
                    ) : (
                      <CheckCircle className="h-4 w-4 text-emerald-400" />
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <Link to={`/instances/${e.instance_id}`} className="text-emerald-400 hover:underline">
                      {e.instance_name}
                    </Link>
                  </td>
                  <td className="px-3 py-2 text-slate-400">{e.location || "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs">{e.product_version}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {e.product_latest && e.product_latest !== e.product_version ? (
                      <span className="text-amber-400">{e.product_latest}</span>
                    ) : (
                      e.product_latest || "—"
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {e.updates_available > 0 ? (
                      <span className="text-amber-400">{e.updates_available}</span>
                    ) : (
                      <span className="text-slate-500">0</span>
                    )}
                    {e.needs_reboot && (
                      <span className="ml-1 text-xs text-red-400">(reboot)</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">{e.last_check || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function KpiTile({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3">
      <p className="text-xs text-slate-500">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );
}
