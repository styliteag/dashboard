import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  Cpu,
  HardDrive,
  MemoryStick,
  Clock,
  Server,
  RefreshCw,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import { api } from "../lib/api";
import type { Instance, SystemStatus, MetricResponse } from "../lib/types";
import IPsecSection from "../components/IPsecSection";
import FirmwareSection from "../components/FirmwareSection";

const RANGES = ["1h", "6h", "24h", "7d", "30d"] as const;
type Range = (typeof RANGES)[number];

const METRICS = [
  { key: "cpu.total", label: "CPU %", color: "#10b981" },
  { key: "memory.used_pct", label: "RAM %", color: "#6366f1" },
] as const;

export default function InstanceDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [range, setRange] = useState<Range>("24h");

  const { data: instance } = useQuery({
    queryKey: ["instance", id],
    queryFn: () => api.get<Instance>(`/api/instances/${id}`),
  });

  const {
    data: status,
    isLoading: statusLoading,
    refetch: refetchStatus,
  } = useQuery({
    queryKey: ["instance-status", id],
    queryFn: () => api.get<SystemStatus>(`/api/instances/${id}/status`),
    refetchInterval: 30_000,
    retry: 1,
  });

  return (
    <div>
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link to="/" className="text-slate-500 hover:text-slate-300">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <h1 className="text-xl font-semibold">
          {instance?.name ?? `Instance ${id}`}
        </h1>
        {instance?.location && (
          <span className="text-sm text-slate-500">{instance.location}</span>
        )}
        <button
          onClick={() => refetchStatus()}
          className="ml-auto flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Status tiles */}
      {statusLoading ? (
        <p className="mt-6 text-slate-500">Lade Status…</p>
      ) : status ? (
        <>
          <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            <Tile
              icon={<Cpu className="h-5 w-5 text-emerald-400" />}
              label="CPU"
              value={`${status.cpu.total.toFixed(1)}%`}
            />
            <Tile
              icon={<MemoryStick className="h-5 w-5 text-indigo-400" />}
              label="RAM"
              value={`${status.memory.used_pct.toFixed(1)}%`}
              sub={`${status.memory.used_mb.toFixed(0)} / ${status.memory.total_mb.toFixed(0)} MB`}
            />
            {status.disks.slice(0, 1).map((d) => (
              <Tile
                key={d.mountpoint}
                icon={<HardDrive className="h-5 w-5 text-amber-400" />}
                label={`Disk ${d.mountpoint}`}
                value={`${d.used_pct.toFixed(1)}%`}
              />
            ))}
            <Tile
              icon={<Clock className="h-5 w-5 text-sky-400" />}
              label="Uptime"
              value={status.uptime ?? "—"}
            />
            <Tile
              icon={<Server className="h-5 w-5 text-slate-400" />}
              label="Version"
              value={status.version ?? "—"}
            />
          </div>

          {/* Interfaces table */}
          {status.interfaces.length > 0 && (
            <section className="mt-6">
              <h2 className="text-sm font-semibold text-slate-400">
                Interfaces
              </h2>
              <div className="mt-2 overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-sm">
                  <thead className="bg-slate-900 text-left text-xs text-slate-500">
                    <tr>
                      <th className="px-3 py-2">Name</th>
                      <th className="px-3 py-2">Status</th>
                      <th className="px-3 py-2">Address</th>
                      <th className="px-3 py-2 text-right">RX</th>
                      <th className="px-3 py-2 text-right">TX</th>
                    </tr>
                  </thead>
                  <tbody>
                    {status.interfaces.map((iface) => (
                      <tr
                        key={iface.name}
                        className="border-t border-slate-800"
                      >
                        <td className="px-3 py-2 font-mono">{iface.name}</td>
                        <td className="px-3 py-2">
                          <span
                            className={
                              iface.status.includes("up")
                                ? "text-emerald-400"
                                : "text-red-400"
                            }
                          >
                            {iface.status}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-slate-400">
                          {iface.address ?? "—"}
                        </td>
                        <td className="px-3 py-2 text-right font-mono">
                          {formatBytes(iface.bytes_received)}
                        </td>
                        <td className="px-3 py-2 text-right font-mono">
                          {formatBytes(iface.bytes_transmitted)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      ) : (
        <p className="mt-6 text-red-400">Status nicht verfuegbar.</p>
      )}

      {/* Metrics charts */}
      <section className="mt-8">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-400">Metriken</h2>
          <div className="flex gap-1">
            {RANGES.map((r) => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`rounded-md px-2 py-1 text-xs ${
                  range === r
                    ? "bg-emerald-600 text-white"
                    : "text-slate-400 hover:bg-slate-800"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 grid gap-6 lg:grid-cols-2">
          {METRICS.map((m) => (
            <MetricChart
              key={m.key}
              instanceId={Number(id)}
              metric={m.key}
              label={m.label}
              color={m.color}
              range={range}
            />
          ))}
        </div>
      </section>

      {/* IPsec (US-4.1..4.5) */}
      <IPsecSection instanceId={Number(id)} />

      {/* Firmware (US-5.1..5.3) */}
      <FirmwareSection instanceId={Number(id)} instanceName={instance?.name ?? ""} />
    </div>
  );
}

// ----- Sub-components -------------------------------------------------------

function Tile({
  icon,
  label,
  value,
  sub,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex items-center gap-2 text-xs text-slate-500">
        {icon} {label}
      </div>
      <p className="mt-1 text-lg font-semibold">{value}</p>
      {sub && <p className="text-xs text-slate-500">{sub}</p>}
    </div>
  );
}

function MetricChart({
  instanceId,
  metric,
  label,
  color,
  range,
}: {
  instanceId: number;
  metric: string;
  label: string;
  color: string;
  range: Range;
}) {
  const { data } = useQuery({
    queryKey: ["metrics", instanceId, metric, range],
    queryFn: () =>
      api.get<MetricResponse>(
        `/api/instances/${instanceId}/metrics?metric=${metric}&range=${range}`,
      ),
    refetchInterval: 60_000,
  });

  const points =
    data?.points.map((p) => ({
      ts: new Date(p.ts).toLocaleTimeString("de-DE", {
        hour: "2-digit",
        minute: "2-digit",
      }),
      value: p.value,
    })) ?? [];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <h3 className="mb-3 text-xs text-slate-500">{label}</h3>
      {points.length === 0 ? (
        <p className="py-8 text-center text-sm text-slate-600">
          Keine Daten fuer diesen Zeitraum.
        </p>
      ) : (
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={points}>
            <defs>
              <linearGradient id={`grad-${metric}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                <stop offset="95%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis
              dataKey="ts"
              tick={{ fontSize: 10, fill: "#64748b" }}
              interval="preserveStartEnd"
            />
            <YAxis
              tick={{ fontSize: 10, fill: "#64748b" }}
              domain={[0, 100]}
              width={35}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#0f172a",
                border: "1px solid #1e293b",
                fontSize: 12,
              }}
            />
            <Area
              type="monotone"
              dataKey="value"
              stroke={color}
              fillOpacity={1}
              fill={`url(#grad-${metric})`}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ----- Helpers --------------------------------------------------------------

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
