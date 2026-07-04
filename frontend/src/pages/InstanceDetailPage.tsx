import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Cpu, HardDrive, MemoryStick, Clock, Server } from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  ReferenceLine,
} from "recharts";
import { api } from "../lib/api";
import { fmtTimeShort } from "../lib/datetime";
import type { Instance, SystemStatus, MetricResponse } from "../lib/types";
import InstanceHeader from "../components/InstanceHeader";
import EditInstanceDialog from "../components/EditInstanceDialog";
import AgentSection from "../components/AgentSection";
import AgentRuntimeSection from "../components/AgentRuntimeSection";
import ChecksSection from "../components/ChecksSection";
import NotesSection from "../components/NotesSection";
import CheckHistorySection from "../components/CheckHistorySection";
import SystemHealthSection from "../components/SystemHealthSection";
import ServicesSection from "../components/ServicesSection";
import ConfigSection from "../components/ConfigSection";
import CertificatesSection from "../components/CertificatesSection";
import GatewaySection from "../components/GatewaySection";
import InterfacesSection from "../components/InterfacesSection";
import IPsecSection from "../components/IPsecSection";
import ConnectivitySection from "../components/ConnectivitySection";
import FirmwareSection from "../components/FirmwareSection";
import FirewallLogSection from "../components/FirewallLogSection";
import LogSnapshotsSection from "../components/LogSnapshotsSection";
import AiLogAnalysisSection from "../components/AiLogAnalysisSection";

const RANGES = ["1h", "6h", "24h", "7d", "30d"] as const;
type Range = (typeof RANGES)[number];

const METRICS = [
  { key: "cpu.total", label: "CPU %", color: "#10b981" },
  { key: "memory.used_pct", label: "RAM %", color: "#6366f1" },
  { key: "load.1m", label: "Load (1m)", color: "#f59e0b" },
  { key: "pf.states_pct", label: "pf states %", color: "#0ea5e9" },
] as const;

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "network", label: "Network" },
  { key: "security", label: "VPN" },
  { key: "connectivity", label: "Connectivity" },
  { key: "log", label: "Log" },
  { key: "firmware", label: "Firmware" },
  { key: "agent", label: "Agent" },
] as const;
type Tab = (typeof TABS)[number]["key"];

export default function InstanceDetailPage() {
  const { id } = useParams<{ id: string }>();
  const nid = Number(id);
  const [range, setRange] = useState<Range>("24h");
  const [editOpen, setEditOpen] = useState(false);
  const [tab, setTab] = useState<Tab>(
    () => (localStorage.getItem("instance.tab") as Tab) || "overview",
  );
  const selectTab = (t: Tab) => {
    localStorage.setItem("instance.tab", t);
    setTab(t);
  };

  const { data: instance } = useQuery({
    queryKey: ["instance", id],
    queryFn: () => api.get<Instance>(`/api/instances/${id}`),
  });

  // Securepoint is direct-only — no agent mode, so hide the agent-only tabs
  // (Agent + Connectivity, both of which need the on-box agent).
  const isSecurepoint = instance?.device_type === "securepoint";
  const tabs = isSecurepoint
    ? TABS.filter((t) => t.key !== "agent" && t.key !== "connectivity")
    : TABS;

  // The selected tab persists across instances; if it's not available here
  // (e.g. "agent" on a Securepoint box), fall back to overview.
  useEffect(() => {
    if (!tabs.some((t) => t.key === tab)) {
      setTab("overview");
    }
  }, [tabs, tab]);

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
      <InstanceHeader
        instance={instance}
        status={status}
        fallbackId={id}
        onRefresh={() => refetchStatus()}
        onEdit={() => setEditOpen(true)}
      />

      {/* Tabs */}
      <div className="mt-5 flex flex-wrap gap-1 border-b border-slate-800">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => selectTab(t.key)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm transition-colors ${
              tab === t.key
                ? "border-emerald-500 text-slate-100"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Overview: KPIs + metrics + service checks */}
      {tab === "overview" && (
        <>
          {statusLoading ? (
            <p className="mt-6 text-slate-500">Loading status…</p>
          ) : status ? (
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
                value={status.uptime || "—"}
              />
              <Tile
                icon={<Server className="h-5 w-5 text-slate-400" />}
                label="Version"
                value={status.version || "—"}
              />
            </div>
          ) : (
            <p className="mt-6 text-red-400">Status not available.</p>
          )}

          <NotesSection instanceId={nid} />

          <section className="mt-8">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-400">Metrics</h2>
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
                  instanceId={nid}
                  metric={m.key}
                  label={m.label}
                  color={m.color}
                  range={range}
                />
              ))}
              {/* Agent collection runtime (push agents only; ms -> s, WARN line at 10s).
                  Empty for direct-poll instances, like the load/pf charts above. */}
              <MetricChart
                instanceId={nid}
                metric="agent.collect_ms"
                label="Agent collect (s)"
                color="#f472b6"
                range={range}
                domain={[0, "auto"]}
                scale={1000}
                refY={10}
              />
            </div>
          </section>

          <SystemHealthSection instanceId={nid} />

          <ChecksSection instanceId={nid} />

          <CheckHistorySection instanceId={nid} />

          <ConfigSection instanceId={nid} />

          <CertificatesSection instanceId={nid} />

          <ServicesSection instanceId={nid} />
        </>
      )}

      {/* Network: interfaces (live throughput) + gateways */}
      {tab === "network" && (
        <div>
          <InterfacesSection instanceId={nid} />
          <GatewaySection instanceId={nid} />
        </div>
      )}

      {/* VPN: IPsec tunnels */}
      {tab === "security" && (
        <div>
          <IPsecSection
            instanceId={nid}
            pingSupported={instance?.agent_mode ?? false}
            diagnoseSupported={
              (instance?.agent_mode ?? false) || instance?.device_type === "securepoint"
            }
            stale={instance?.stale ?? false}
            staleSeconds={instance?.stale_seconds ?? null}
          />
        </div>
      )}

      {/* Connectivity: standalone (tunnel-independent) ping monitors */}
      {tab === "connectivity" && (
        <div>
          <ConnectivitySection instanceId={nid} pingSupported={instance?.agent_mode ?? false} />
        </div>
      )}

      {/* Log: firewall log + stored snapshots + AI log analysis */}
      {tab === "log" && (
        <div>
          <FirewallLogSection instanceId={nid} />
          <LogSnapshotsSection instanceId={nid} />
          <AiLogAnalysisSection instanceId={nid} />
        </div>
      )}

      {/* Firmware */}
      {tab === "firmware" && (
        <div>
          <FirmwareSection
            instanceId={nid}
            instanceName={instance?.name ?? ""}
            agentMode={instance?.agent_mode ?? false}
            firmwareLocked={instance?.firmware_locked ?? false}
          />
        </div>
      )}

      {/* Agent — hidden for Securepoint (direct-only) */}
      {tab === "agent" && !isSecurepoint && (
        <div className="space-y-6">
          <AgentRuntimeSection status={status} />
          <AgentSection instanceId={nid} agentMode={instance?.agent_mode ?? false} />
        </div>
      )}

      {editOpen && instance && (
        <EditInstanceDialog instance={instance} onClose={() => setEditOpen(false)} />
      )}
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
  domain = [0, 100],
  scale = 1,
  refY,
}: {
  instanceId: number;
  metric: string;
  label: string;
  color: string;
  range: Range;
  /** Y-axis domain. Defaults to [0, 100] for percentage metrics. */
  domain?: [number | string, number | string];
  /** Divide raw values by this before plotting (e.g. 1000 for ms -> s). */
  scale?: number;
  /** Optional dashed reference line (in plotted/scaled units), e.g. a WARN threshold. */
  refY?: number;
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
      ts: fmtTimeShort(p.ts),
      value: p.value / scale,
    })) ?? [];

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <h3 className="mb-3 text-xs text-slate-500">{label}</h3>
      {points.length === 0 ? (
        <p className="py-8 text-center text-sm text-slate-600">No data for this range.</p>
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
            <YAxis tick={{ fontSize: 10, fill: "#64748b" }} domain={domain} width={35} />
            <Tooltip
              contentStyle={{
                backgroundColor: "#0f172a",
                border: "1px solid #1e293b",
                fontSize: 12,
              }}
            />
            {refY != null && (
              <ReferenceLine y={refY} stroke="#f59e0b" strokeDasharray="4 4" strokeOpacity={0.7} />
            )}
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
