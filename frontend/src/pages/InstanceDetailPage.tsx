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
import { deviceCaps } from "../lib/capabilities";
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
import ConfigBackupsSection from "../components/ConfigBackupsSection";
import ConfigSection from "../components/ConfigSection";
import CertificatesSection from "../components/CertificatesSection";
import ExternalIpSection from "../components/ExternalIpSection";
import GatewaySection from "../components/GatewaySection";
import InterfacesSection from "../components/InterfacesSection";
import TopTalkersSection from "../components/TopTalkersSection";
import IPsecSection from "../components/IPsecSection";
import ConnectivitySection from "../components/ConnectivitySection";
import FirmwareSection from "../components/FirmwareSection";
import FirewallLogSection from "../components/FirewallLogSection";
import FirewallRulesSection from "../components/FirewallRulesSection";
import LogSnapshotsSection from "../components/LogSnapshotsSection";
import AiLogAnalysisSection from "../components/AiLogAnalysisSection";
import PacketCaptureSection from "../components/PacketCaptureSection";

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
  { key: "config", label: "Config" },
  { key: "checks", label: "Checks" },
  { key: "network", label: "Network" },
  { key: "capture", label: "Capture" },
  { key: "firewall", label: "Firewall" },
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

  // Tab visibility comes from the central capability map (DR-8) — e.g. Securepoint
  // is direct-only (no agent tabs), the rule editor is OPNsense-specific.
  const caps = deviceCaps(instance?.device_type);
  const tabs = TABS.filter((t) => {
    if (t.key === "agent" && !caps.agent) return false;
    if (t.key === "connectivity" && !caps.connectivity) return false;
    if (t.key === "capture" && !caps.capture) return false;
    if (t.key === "firewall" && !caps.firewallRules) return false;
    if (t.key === "security" && !caps.tunnels) return false;
    if (t.key === "config" && !caps.configBackup) return false;
    return true;
  });

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
            {t.key === "firmware" ? caps.updatesLabel : t.label}
          </button>
        ))}
      </div>

      {/* Overview: KPIs + metrics + system health + certificates + services */}
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

          {status?.console_password_protected && (
            <div className="mt-4 rounded-md border border-amber-700/60 bg-amber-900/10 px-3 py-2 text-sm text-amber-300">
              <span className="font-medium">Console password protection enabled.</span> We prefer no
              password on the console. Disable “Password protect the console menu” under System →
              Settings → Administration → Console / Serial Communications.
            </div>
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

          <CertificatesSection instanceId={nid} />

          <ServicesSection instanceId={nid} />
        </>
      )}

      {/* Config: last revision + versioned encrypted backups with diff viewer */}
      {tab === "config" && (
        <div className="space-y-6">
          <ConfigSection instanceId={nid} />
          {/* key: remount on instance switch so a carried-over version selection
              doesn't fire a diff under the wrong instance. */}
          <ConfigBackupsSection key={nid} instanceId={nid} />
        </div>
      )}

      {/* Checks: current service check states (with per-box notify/export toggles) + recent state transition history */}
      {tab === "checks" && (
        <div>
          <ChecksSection instanceId={nid} />
          <CheckHistorySection instanceId={nid} />
        </div>
      )}

      {/* Network: public IP / NAT + interfaces (live throughput) + gateways + top talkers */}
      {tab === "network" && (
        <div>
          <ExternalIpSection instanceId={nid} />
          <InterfacesSection instanceId={nid} />
          <GatewaySection instanceId={nid} />
          <TopTalkersSection instanceId={nid} />
        </div>
      )}

      {/* Capture: remote bounded tcpdump via agent + nice in-browser viewer (new tab) */}
      {/* key: remount on instance switch so a prior capture's result (and its
          capture-scoped download/view links) can't show under another instance. */}
      {tab === "capture" && <PacketCaptureSection key={nid} instanceId={nid} />}

      {/* Firewall: OPNsense firewall rules through the core API */}
      {tab === "firewall" && caps.firewallRules && (
        <div>
          <FirewallRulesSection instanceId={nid} />
        </div>
      )}

      {/* VPN: IPsec tunnels */}
      {tab === "security" && (
        <div>
          <IPsecSection
            instanceId={nid}
            pingSupported={instance?.agent_mode ?? false}
            diagnoseSupported={(instance?.agent_mode ?? false) || caps.sshEnrichment}
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

      {/* Log: firewall log (pf platforms) + stored snapshots + AI log analysis */}
      {tab === "log" && (
        <div>
          {caps.firewallLog && <FirewallLogSection instanceId={nid} />}
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

      {/* Agent — only for agent-capable device types (hidden e.g. for Securepoint) */}
      {tab === "agent" && caps.agent && (
        <div className="space-y-6">
          <AgentRuntimeSection status={status} />
          <AgentSection
            instanceId={nid}
            agentMode={instance?.agent_mode ?? false}
            deviceType={instance?.device_type}
          />
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
