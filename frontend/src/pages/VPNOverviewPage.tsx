import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Shield, Link2, Unlink, RotateCw, Search, ChevronRight, ChevronDown } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type {
  IPsecChild,
  IPsecPingMonitor,
  IPsecServiceStatus,
  TunnelActionResponse,
} from "../lib/types";
import { Phase2Badge, Phase2ChildList, PingSummary } from "../components/IPsecPhase2";
import PingMonitorDialog from "../components/PingMonitorDialog";

interface GlobalTunnel {
  instance_id: number;
  instance_name: string;
  tunnel_id: string;
  unique_id: string;
  description: string;
  remote: string;
  local: string;
  phase1_status: string;
  phase2_up: number;
  phase2_total: number;
  seconds_established: number;
  bytes_in: number;
  bytes_out: number;
  children: IPsecChild[];
}

interface DialogTarget {
  instanceId: number;
  tunnelId: string;
  tunnelDescription: string;
  child: IPsecChild;
  existing: IPsecPingMonitor | null;
}

/** Expanded Phase-2 detail for one tunnel; fetches that instance's monitors. */
function ExpandedPhase2({
  tunnel,
  onConfigure,
}: {
  tunnel: GlobalTunnel;
  onConfigure: (tunnel: GlobalTunnel, child: IPsecChild, existing: IPsecPingMonitor | null) => void;
}) {
  const { data: monitors = [] } = useQuery({
    queryKey: ["ipsec-ping-monitors", tunnel.instance_id],
    queryFn: () =>
      api.get<IPsecPingMonitor[]>(`/api/instances/${tunnel.instance_id}/ipsec/ping-monitors`),
  });
  return (
    <Phase2ChildList
      tunnelId={tunnel.tunnel_id}
      entries={tunnel.children ?? []}
      monitors={monitors}
      onConfigure={(child, existing) => onConfigure(tunnel, child, existing)}
    />
  );
}

interface GlobalVPNResponse {
  tunnels: GlobalTunnel[];
  total: number;
  up: number;
  down: number;
}

function isUp(phase1_status: string): boolean {
  const s = phase1_status.toLowerCase();
  return s.includes("established") || s.includes("connected");
}

export default function VPNOverviewPage() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "up" | "down">("all");

  const queryClient = useQueryClient();
  const [actionMsg, setActionMsg] = useState<{ ok: boolean; text: string } | null>(null);
  // Per-tunnel in-flight tracking — an action only disables ITS row, never the
  // whole list, and several tunnels can be actioned concurrently.
  const [pending, setPending] = useState<Set<string>>(new Set());
  const rowKey = (t: GlobalTunnel) => `${t.instance_id}-${t.tunnel_id}`;
  const setBusy = (k: string, on: boolean) =>
    setPending((s) => {
      const n = new Set(s);
      if (on) n.add(k);
      else n.delete(k);
      return n;
    });
  const flash = (m: { ok: boolean; text: string }) => {
    setActionMsg(m);
    setTimeout(() => setActionMsg(null), 5000);
  };

  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const toggleExpand = (k: string) =>
    setExpanded((s) => {
      const n = new Set(s);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });
  const [dialog, setDialog] = useState<DialogTarget | null>(null);

  // Targeted refresh: after an action, refetch only the acted instance's IPsec
  // and patch its rows into the overview cache — avoids a full cross-instance
  // fan-out on every click. Falls back to a normal refetch on error.
  const patchInstance = async (instanceId: number) => {
    try {
      const fresh = await api.get<IPsecServiceStatus>(`/api/instances/${instanceId}/ipsec`);
      const byId = new Map(fresh.tunnels.map((ft) => [ft.id, ft]));
      queryClient.setQueryData<GlobalVPNResponse>(["vpn-overview"], (old) => {
        if (!old) return old;
        const tunnels = old.tunnels.map((t) => {
          if (t.instance_id !== instanceId) return t;
          const ft = byId.get(t.tunnel_id);
          if (!ft) return t;
          return {
            ...t,
            phase1_status: ft.phase1_status,
            unique_id: ft.unique_id,
            phase2_up: ft.phase2_up,
            phase2_total: ft.phase2_total,
            seconds_established: ft.seconds_established,
            bytes_in: ft.bytes_in,
            bytes_out: ft.bytes_out,
            children: ft.children,
          };
        });
        const up = tunnels.filter((t) => isUp(t.phase1_status)).length;
        return { ...old, tunnels, total: tunnels.length, up, down: tunnels.length - up };
      });
    } catch {
      queryClient.invalidateQueries({ queryKey: ["vpn-overview"] });
    }
  };

  const { data, isLoading } = useQuery({
    queryKey: ["vpn-overview"],
    queryFn: () => api.get<GlobalVPNResponse>("/api/vpn/overview"),
    refetchInterval: 30_000,
  });

  const disconnectMut = useMutation({
    mutationFn: (t: GlobalTunnel) =>
      api.post<TunnelActionResponse>(
        `/api/instances/${t.instance_id}/ipsec/disconnect/${t.unique_id || t.tunnel_id}`,
      ),
    onMutate: (t) => setBusy(rowKey(t), true),
    onSettled: (_d, _e, t) => setBusy(rowKey(t), false),
    onSuccess: (r, t) => {
      flash({ ok: r.success, text: r.success ? "Disconnected" : r.message });
      patchInstance(t.instance_id);
    },
    onError: (e) => flash({ ok: false, text: e instanceof ApiError ? e.message : "Error" }),
  });

  // Reconnect = terminate the live SA (if up, best-effort) then re-initiate,
  // via the existing connect/disconnect endpoints (works in agent mode).
  const reconnectMut = useMutation({
    mutationFn: async (t: GlobalTunnel) => {
      if (isUp(t.phase1_status) && t.unique_id) {
        await api
          .post(`/api/instances/${t.instance_id}/ipsec/disconnect/${t.unique_id}`)
          .catch(() => undefined);
      }
      return api.post<TunnelActionResponse>(
        `/api/instances/${t.instance_id}/ipsec/connect/${t.tunnel_id}`,
      );
    },
    onMutate: (t) => setBusy(rowKey(t), true),
    onSettled: (_d, _e, t) => setBusy(rowKey(t), false),
    onSuccess: (r, t) => {
      flash({ ok: r.success, text: r.success ? "Reconnected" : r.message });
      patchInstance(t.instance_id);
    },
    onError: (e) => flash({ ok: false, text: e instanceof ApiError ? e.message : "Error" }),
  });

  const filtered = (data?.tunnels ?? []).filter((t) => {
    const matchSearch =
      t.instance_name.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase()) ||
      t.remote.toLowerCase().includes(search.toLowerCase());
    const matchFilter =
      filter === "all" || (filter === "up" && isUp(t.phase1_status)) || (filter === "down" && !isUp(t.phase1_status));
    return matchSearch && matchFilter;
  });

  return (
    <div>
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <Shield className="h-5 w-5 text-slate-400" /> VPN overview (all instances)
      </h1>

      {/* KPIs */}
      {data && (
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <KpiTile label="Tunnels total" value={data.total} color="text-slate-100" />
          <KpiTile label="Connected" value={data.up} color="text-emerald-400" />
          <KpiTile label="Disconnected" value={data.down} color="text-red-400" />
        </div>
      )}

      {/* Search + status filter */}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search by instance, tunnel, remote…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 py-2 pl-9 pr-3 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </div>
        {(["all", "up", "down"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`rounded-md px-3 py-1.5 text-xs ${
              filter === f ? "bg-emerald-600 text-white" : "text-slate-400 hover:bg-slate-800"
            }`}
          >
            {{ all: "All", up: "Connected", down: "Disconnected" }[f]}
          </button>
        ))}
      </div>

      {actionMsg && (
        <div
          className={`mt-3 rounded-lg px-3 py-2 text-sm ${
            actionMsg.ok ? "bg-emerald-900/40 text-emerald-300" : "bg-red-900/40 text-red-300"
          }`}
        >
          {actionMsg.text}
        </div>
      )}

      {isLoading ? (
        <p className="mt-6 text-slate-500">Loading VPN status of all instances…</p>
      ) : filtered.length === 0 ? (
        <p className="mt-6 text-slate-500">No tunnels found.</p>
      ) : (
        <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Instance</th>
                <th className="px-3 py-2">Tunnel</th>
                <th className="px-3 py-2">Remote</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Phase 2</th>
                <th className="px-3 py-2">Uptime</th>
                <th className="px-3 py-2 text-right">IN</th>
                <th className="px-3 py-2 text-right">OUT</th>
                <th className="px-3 py-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t, i) => {
                const up = isUp(t.phase1_status);
                const k = `${rowKey(t)}-${i}`;
                const isOpen = expanded.has(k);
                const hasChildren = (t.children?.length ?? 0) > 0;
                return (
                  <Fragment key={k}>
                    <tr className="border-t border-slate-800">
                      <td className="px-3 py-2">
                        <Link
                          to={`/instances/${t.instance_id}`}
                          className="text-emerald-400 hover:underline"
                        >
                          {t.instance_name}
                        </Link>
                      </td>
                      <td className="px-3 py-2">
                        <button
                          onClick={() => toggleExpand(k)}
                          disabled={!hasChildren}
                          className="inline-flex items-center gap-1 hover:text-emerald-400 disabled:opacity-40"
                        >
                          {hasChildren ? (
                            isOpen ? (
                              <ChevronDown className="h-3 w-3" />
                            ) : (
                              <ChevronRight className="h-3 w-3" />
                            )
                          ) : (
                            <span className="inline-block w-3" />
                          )}
                          {t.description || t.tunnel_id}
                        </button>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs">{t.remote}</td>
                      <td className="px-3 py-2">
                        <span className={`inline-flex items-center gap-1 ${up ? "text-emerald-400" : "text-red-400"}`}>
                          {up ? <Link2 className="h-3 w-3" /> : <Unlink className="h-3 w-3" />}
                          {t.phase1_status}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <Phase2Badge up={t.phase2_up} total={t.phase2_total} />
                          <PingSummary entries={t.children ?? []} />
                        </div>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-slate-400">
                        {up && t.seconds_established > 0 ? fmtDuration(t.seconds_established) : "—"}
                      </td>
                      <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes_in)}</td>
                      <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes_out)}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center justify-end gap-1">
                          {up && (
                            <button
                              onClick={() => disconnectMut.mutate(t)}
                              disabled={pending.has(rowKey(t))}
                              className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-red-400 hover:bg-slate-800 disabled:opacity-50"
                            >
                              <Unlink className="h-3 w-3" /> Down
                            </button>
                          )}
                          <button
                            onClick={() => reconnectMut.mutate(t)}
                            disabled={pending.has(rowKey(t))}
                            className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-emerald-400 hover:bg-slate-800 disabled:opacity-50"
                          >
                            <RotateCw
                              className={`h-3 w-3 ${pending.has(rowKey(t)) ? "animate-spin" : ""}`}
                            />{" "}
                            Reconnect
                          </button>
                        </div>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="border-t border-slate-800/50 bg-slate-900/40">
                        <td colSpan={9} className="px-3 py-1">
                          <ExpandedPhase2
                            tunnel={t}
                            onConfigure={(tn, child, existing) =>
                              setDialog({
                                instanceId: tn.instance_id,
                                tunnelId: tn.tunnel_id,
                                tunnelDescription: tn.description || tn.tunnel_id,
                                child,
                                existing,
                              })
                            }
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {dialog && (
        <PingMonitorDialog
          instanceId={dialog.instanceId}
          tunnelId={dialog.tunnelId}
          tunnelDescription={dialog.tunnelDescription}
          child={dialog.child}
          existing={dialog.existing}
          onClose={() => setDialog(null)}
        />
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

function fmtDuration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${seconds}s`;
}

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 / 1024).toFixed(1)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
