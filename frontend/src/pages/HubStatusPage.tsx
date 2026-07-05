import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../lib/use-auth";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import KpiTile from "../components/KpiTile";
import { ShellIconLink } from "../components/ShellIconLink";
import { WebUiIconLink } from "../components/WebUiIconLink";
import { api, apiErrorText } from "../lib/api";
import { fmtDateTime, fmtRelative, fmtTimeShort } from "../lib/datetime";
import { fmtDuration } from "../lib/format";
import { useAgentModeMap, useShellEnabledMap } from "../lib/instances";
import type { HubStatsResponse, ServiceAlert } from "../lib/types";

/** Counters that indicate something is wrong — rendered red when non-zero. */
const ERROR_COUNTERS: [string, string][] = [
  ["auth_failures", "Auth failures"],
  ["json_errors", "Bad JSON frames"],
  ["handler_errors", "Handler errors"],
  ["ws_errors", "WS errors"],
  ["unknown_messages", "Unknown messages"],
];

const TRAFFIC_COUNTERS: [string, string][] = [
  ["pushes", "Metric pushes"],
  ["command_results", "Command results"],
  ["tunnel_frames", "Tunnel frames"],
  ["pongs", "Pongs"],
  ["connects", "Connects"],
  ["disconnects", "Disconnects"],
];

export default function HubStatusPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { data, isLoading, error } = useQuery({
    queryKey: ["hub-stats"],
    queryFn: () => api.get<HubStatsResponse>("/api/hub/stats"),
    refetchInterval: 10_000,
  });

  const { data: alerts = [] } = useQuery({
    queryKey: ["alerts"],
    queryFn: () => api.get<ServiceAlert[]>("/api/checks"),
    refetchInterval: 30_000,
  });
  const agentMode = useAgentModeMap();
  const shellEnabled = useShellEnabledMap();

  useEffect(() => {
    if (error && user && !user.is_admin) {
      navigate("/instances", { replace: true });
    }
  }, [error, user, navigate]);

  if (error && !(user && !user.is_admin)) {
    // Direct navigation by a non-admin lands here (403) — the nav link is gated.
    return (
      <div className="py-8 text-center">
        <p className="text-sm text-slate-600">{apiErrorText(error, "Failed to load hub stats")}</p>
        <p className="mt-2 text-xs text-slate-500">
          <Link to="/instances" className="underline hover:text-slate-300">
            Go to Instances
          </Link>
        </p>
      </div>
    );
  }
  if (isLoading || !data) {
    return <p className="py-8 text-center text-sm text-slate-600">Loading…</p>;
  }

  const errorsTotal = ERROR_COUNTERS.reduce((sum, [key]) => sum + (data.counters[key] ?? 0), 0);
  // The newest bucket is the still-filling current minute — report the last full one.
  const perMinute = data.push_rate.length > 1 ? data.push_rate[data.push_rate.length - 2].count : 0;
  const chart = data.push_rate.map((p) => ({ ts: fmtTimeShort(p.ts), count: p.count }));

  // Group CRIT (red) alerts by the tab that owns them, so each chip links to the
  // page where the operator actually fixes it — not to a generic alert list.
  const critAlerts = alerts.filter((a) => a.state === 2);
  const tabCounts = new Map<string, { to: string; label: string; count: number }>();
  for (const a of critAlerts) {
    const tab = alertTab(a.key);
    const prev = tabCounts.get(tab.to);
    tabCounts.set(tab.to, prev ? { ...prev, count: prev.count + 1 } : { ...tab, count: 1 });
  }
  const alertTabs = [...tabCounts.values()].sort((a, b) => b.count - a.count);

  return (
    <div>
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <Activity className="h-5 w-5 text-slate-400" /> Hub status
      </h1>
      <p className="mt-1 text-xs text-slate-500">
        In-memory since {fmtDateTime(data.started_at)} (up {fmtDuration(data.uptime_seconds)}) — a
        backend restart resets these numbers.
      </p>
      <p className="mt-2 text-xs text-slate-400">
        Central hub for monitoring all connected instances, agent activity, message throughput, and
        health.
      </p>

      <div className="mt-4 grid gap-3 sm:grid-cols-4">
        <KpiTile label="Connected agents" value={data.connected_agents} color="text-emerald-400" />
        <KpiTile label="Pushes / min" value={perMinute} color="text-sky-400" />
        <KpiTile label="Pushes total" value={data.counters.pushes ?? 0} color="text-slate-100" />
        <KpiTile
          label="Errors total"
          value={errorsTotal}
          color={errorsTotal > 0 ? "text-red-400" : "text-slate-100"}
        />
      </div>

      <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h3 className="mb-3 text-xs text-slate-500">Metric pushes per minute (last hour)</h3>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={chart}>
            <defs>
              <linearGradient id="grad-hub-pushes" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis
              dataKey="ts"
              tick={{ fontSize: 10, fill: "#64748b" }}
              interval="preserveStartEnd"
            />
            <YAxis tick={{ fontSize: 10, fill: "#64748b" }} allowDecimals={false} width={35} />
            <Tooltip
              contentStyle={{
                backgroundColor: "#0f172a",
                border: "1px solid #1e293b",
                fontSize: 12,
              }}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke="#38bdf8"
              fillOpacity={1}
              fill="url(#grad-hub-pushes)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <h2 className="mt-6 text-sm font-semibold text-slate-300">Error counters</h2>
      <div className="mt-2 grid gap-3 sm:grid-cols-5">
        {ERROR_COUNTERS.map(([key, label]) => (
          <CounterTile key={key} label={label} value={data.counters[key] ?? 0} alert />
        ))}
      </div>

      <h2 className="mt-6 text-sm font-semibold text-slate-300">Red / CRIT alerts by tab</h2>
      {alertTabs.length === 0 ? (
        <p className="mt-2 text-sm text-slate-600">No CRIT alerts.</p>
      ) : (
        <div className="mt-2 flex flex-wrap gap-2">
          {alertTabs.map((t) => (
            <Link
              key={t.to}
              to={t.to}
              className="rounded-lg border border-red-900 bg-red-950/40 px-3 py-1 text-sm hover:bg-red-900/60"
            >
              <span className="text-red-300">{t.label}</span>
              <span className="ml-2 font-semibold text-red-400">{t.count}</span>
            </Link>
          ))}
        </div>
      )}

      <h2 className="mt-6 text-sm font-semibold text-slate-300">Message counters</h2>
      <div className="mt-2 grid gap-3 sm:grid-cols-6">
        {TRAFFIC_COUNTERS.map(([key, label]) => (
          <CounterTile key={key} label={label} value={data.counters[key] ?? 0} />
        ))}
      </div>

      <h2 className="mt-6 text-sm font-semibold text-slate-300">
        Connected agents ({data.agents.length})
      </h2>
      {data.agents.length === 0 ? (
        <p className="mt-2 text-sm text-slate-600">No agents connected (in your groups).</p>
      ) : (
        <div className="mt-2 overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Instance</th>
                <th className="px-3 py-2">Platform</th>
                <th className="px-3 py-2">Agent version</th>
                <th className="px-3 py-2">Connected</th>
                <th className="px-3 py-2">Pushes</th>
                <th className="px-3 py-2">Last push</th>
              </tr>
            </thead>
            <tbody>
              {data.agents.map((a) => (
                <tr key={a.instance_id} className="border-t border-slate-800">
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <Link to={`/instances/${a.instance_id}`} className="hover:text-emerald-400">
                        {a.instance_name}
                      </Link>
                      <WebUiIconLink
                        instanceId={a.instance_id}
                        instanceName={a.instance_name}
                        agentMode={agentMode.get(a.instance_id) ?? true}
                      />
                      <ShellIconLink
                        instanceId={a.instance_id}
                        instanceName={a.instance_name}
                        eligible={agentMode.get(a.instance_id) ?? true}
                        shellEnabled={shellEnabled.get(a.instance_id) ?? false}
                      />
                    </span>
                  </td>
                  <td className="px-3 py-2 text-slate-400">{a.platform || "—"}</td>
                  <td className="px-3 py-2 text-slate-400">{a.agent_version || "—"}</td>
                  <td className="px-3 py-2 text-slate-400" title={fmtDateTime(a.connected_at)}>
                    {fmtRelative(a.connected_at)}
                  </td>
                  <td className="px-3 py-2 text-slate-400">{a.pushes}</td>
                  <td
                    className="px-3 py-2 text-slate-400"
                    title={a.last_push_at ? fmtDateTime(a.last_push_at) : undefined}
                  >
                    {a.last_push_at ? fmtRelative(a.last_push_at) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Map a granular check key to the tab that owns it, so a Hub alert links to the
 * page where it is acted on. Categories mirror backend/src/app/checks/evaluate.py.
 * "Connectivity" is only the ping monitors (connectivity:*) shown on that page —
 * gateway alerts are a different thing (dpinger gateway state) with no overview
 * page, so they go to the alert list alongside the System checks. */
function alertTab(key: string): { to: string; label: string } {
  const cat = key.includes(":") ? key.slice(0, key.indexOf(":")) : key;
  if (cat === "cert") return { to: "/certs", label: "Certificates" };
  if (cat === "ipsec.tunnel" || cat === "ipsec.tunnel_ping" || cat === "ipsec.service") {
    return { to: "/vpn", label: "VPN" };
  }
  if (cat === "connectivity") return { to: "/connectivity", label: "Connectivity" };
  if (cat === "gateway") return { to: "/alerts?q=gateway:", label: "Gateways" };
  if (cat === "firmware") return { to: "/firmware", label: "Firmware" };
  return { to: "/alerts", label: "System" };
}

function CounterTile({ label, value, alert }: { label: string; value: number; alert?: boolean }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3">
      <p className="text-xs text-slate-500">{label}</p>
      <p
        className={`text-lg font-semibold ${alert && value > 0 ? "text-red-400" : "text-slate-200"}`}
      >
        {value}
      </p>
    </div>
  );
}
