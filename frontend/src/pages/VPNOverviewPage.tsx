import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Shield, Link2, Unlink, Search } from "lucide-react";
import { api } from "../lib/api";

interface GlobalTunnel {
  instance_id: number;
  instance_name: string;
  tunnel_id: string;
  description: string;
  remote: string;
  local: string;
  phase1_status: string;
  bytes_in: number;
  bytes_out: number;
}

interface GlobalVPNResponse {
  tunnels: GlobalTunnel[];
  total: number;
  up: number;
  down: number;
}

export default function VPNOverviewPage() {
  const [search, setSearch] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["vpn-overview"],
    queryFn: () => api.get<GlobalVPNResponse>("/api/vpn/overview"),
    refetchInterval: 30_000,
  });

  const filtered = (data?.tunnels ?? []).filter(
    (t) =>
      t.instance_name.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase()) ||
      t.remote.toLowerCase().includes(search.toLowerCase()),
  );

  return (
    <div>
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <Shield className="h-5 w-5 text-slate-400" /> VPN-Uebersicht (alle Instanzen)
      </h1>

      {/* KPIs */}
      {data && (
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <KpiTile label="Tunnel gesamt" value={data.total} color="text-slate-100" />
          <KpiTile label="Verbunden" value={data.up} color="text-emerald-400" />
          <KpiTile label="Getrennt" value={data.down} color="text-red-400" />
        </div>
      )}

      {/* Search */}
      <div className="relative mt-4 max-w-md">
        <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
        <input
          type="text"
          placeholder="Suche nach Instanz, Tunnel, Remote…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full rounded-lg border border-slate-700 bg-slate-800 py-2 pl-9 pr-3 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
        />
      </div>

      {isLoading ? (
        <p className="mt-6 text-slate-500">Lade VPN-Status aller Instanzen…</p>
      ) : filtered.length === 0 ? (
        <p className="mt-6 text-slate-500">Keine Tunnel gefunden.</p>
      ) : (
        <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Instanz</th>
                <th className="px-3 py-2">Tunnel</th>
                <th className="px-3 py-2">Remote</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2 text-right">IN</th>
                <th className="px-3 py-2 text-right">OUT</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t, i) => {
                const up =
                  t.phase1_status.toLowerCase().includes("established") ||
                  t.phase1_status.toLowerCase().includes("connected");
                return (
                  <tr key={`${t.instance_id}-${t.tunnel_id}-${i}`} className="border-t border-slate-800">
                    <td className="px-3 py-2">
                      <Link
                        to={`/instances/${t.instance_id}`}
                        className="text-emerald-400 hover:underline"
                      >
                        {t.instance_name}
                      </Link>
                    </td>
                    <td className="px-3 py-2">{t.description || t.tunnel_id}</td>
                    <td className="px-3 py-2 font-mono text-xs">{t.remote}</td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center gap-1 ${up ? "text-emerald-400" : "text-red-400"}`}>
                        {up ? <Link2 className="h-3 w-3" /> : <Unlink className="h-3 w-3" />}
                        {t.phase1_status}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes_in)}</td>
                    <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes_out)}</td>
                  </tr>
                );
              })}
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

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 / 1024).toFixed(1)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
