import { Fragment, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Shield,
  Link2,
  Unlink,
  RotateCw,
  Search,
  ChevronRight,
  ChevronDown,
  History,
} from "lucide-react";
import { api, ApiError } from "../lib/api";
import type {
  IPsecChild,
  IPsecPingMonitor,
  IPsecServiceStatus,
  TunnelActionResponse,
} from "../lib/types";
import { Phase2Badge, Phase2ChildList, Phase2DupNote, PingSummary } from "../components/IPsecPhase2";
import { WebUiIconLink } from "../components/WebUiIconLink";
import { worstPing } from "../lib/ipsec-ping";
import { useSort, type Accessors } from "../lib/use-sort";
import SortHeader from "../components/SortHeader";
import PingMonitorDialog from "../components/PingMonitorDialog";
import TunnelHistoryDialog from "../components/TunnelHistoryDialog";

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
  tags?: string[];
  agent_mode?: boolean;
  stale?: boolean;
  stale_seconds?: number | null;
  children: IPsecChild[];
  ike_init_spi?: string;
  ike_resp_spi?: string;
  peer_instance_id?: number | null;
  peer_instance_name?: string | null;
  peer_tunnel_id?: string | null;
}

interface TunnelGroup {
  members: GlobalTunnel[];
  paired: boolean;
}

/** Group the two ends of the same tunnel (peer pairing) so they render together. */
function buildGroups(tunnels: GlobalTunnel[]): TunnelGroup[] {
  const byKey = new Map<string, GlobalTunnel>();
  for (const t of tunnels) byKey.set(`${t.instance_id}-${t.tunnel_id}`, t);
  const seen = new Set<string>();
  const groups: TunnelGroup[] = [];
  for (const t of tunnels) {
    const k = `${t.instance_id}-${t.tunnel_id}`;
    if (seen.has(k)) continue;
    const peerK = t.peer_instance_id != null ? `${t.peer_instance_id}-${t.peer_tunnel_id}` : null;
    const peer = peerK ? byKey.get(peerK) : undefined;
    if (peer && peerK && !seen.has(peerK)) {
      groups.push({ members: [t, peer], paired: true });
      seen.add(k);
      seen.add(peerK);
    } else {
      groups.push({ members: [t], paired: false });
      seen.add(k);
    }
  }
  return groups;
}

/** Combined health of a paired link, for the group header badge. */
function pairHealth(a: GlobalTunnel, b: GlobalTunnel): { cls: string; label: string } {
  // Staleness wins: if either end's agent is silent, this side's status is
  // last-known, not live — never report a stale pair as "both up" (it must stay
  // expanded, not collapse as healthy).
  if (a.stale || b.stale) return { cls: "bg-amber-600/20 text-amber-400", label: "stale" };
  const aUp = isUp(a.phase1_status);
  const bUp = isUp(b.phase1_status);
  if (aUp !== bUp) return { cls: "bg-red-600/20 text-red-400", label: "status mismatch" };
  if (!aUp && !bUp) return { cls: "bg-slate-700 text-slate-300", label: "both down" };
  // Both Phase 1 up — but "established" doesn't mean traffic flows. Fold the
  // Phase-2 ping monitor into the health so a tunnel that's up yet not passing
  // traffic isn't reported "both up" and auto-collapsed (the whole point of the
  // collapse is to hide *healthy* pairs). Symmetric failure (both ends fail) is
  // the usual outage shape, so rank by the worst end across both — a plain
  // mismatch check misses it. No monitor configured (state "none") stays green.
  const pa = worstPing(a.children ?? []);
  const pb = worstPing(b.children ?? []);
  const worst = worstPing([...(a.children ?? []), ...(b.children ?? [])]);
  if (worst === "fail") return { cls: "bg-red-600/20 text-red-400", label: "ping fail" };
  if (pa !== pb) return { cls: "bg-amber-600/20 text-amber-400", label: "ping mismatch" };
  if (worst === "error") return { cls: "bg-amber-600/20 text-amber-400", label: "ping error" };
  return { cls: "bg-emerald-600/20 text-emerald-400", label: "both up" };
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
    enabled: tunnel.agent_mode ?? false, // ping monitors are agent-only
  });
  return (
    <Phase2ChildList
      tunnelId={tunnel.tunnel_id}
      entries={tunnel.children ?? []}
      monitors={monitors}
      pingSupported={tunnel.agent_mode ?? false}
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

const VPN_ACCESSORS: Accessors<GlobalTunnel> = {
  instance: (t) => t.instance_name.toLowerCase(),
  tunnel: (t) => (t.description || t.tunnel_id).toLowerCase(),
  remote: (t) => t.remote,
  status: (t) => (isUp(t.phase1_status) ? 0 : 1),
  phase2: (t) => t.phase2_up,
  uptime: (t) => t.seconds_established,
  in: (t) => t.bytes_in,
  out: (t) => t.bytes_out,
};

export default function VPNOverviewPage() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "up" | "down">("all");
  const [activeTag, setActiveTag] = useState<string | null>(null);
  // Pairing/aggregation is optional: off → a flat, sortable list.
  const [grouped, setGrouped] = useState(() => localStorage.getItem("vpn.grouped") !== "0");
  const setGroupedPersisted = (v: boolean) => {
    localStorage.setItem("vpn.grouped", v ? "1" : "0");
    setGrouped(v);
  };

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
  const [historyTarget, setHistoryTarget] = useState<GlobalTunnel | null>(null);

  // Paired-group collapse: healthy ("both up") pairs collapse to just their header
  // by default (problems stay expanded). Two explicit-override sets let the user
  // open/close individual groups and the "Expand/Collapse all" button.
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const [closedGroups, setClosedGroups] = useState<Set<string>>(new Set());
  const groupKey = (g: TunnelGroup) => g.members.map(rowKey).join("|");
  const isGroupOpen = (g: TunnelGroup, key: string, bothUp: boolean): boolean => {
    if (openGroups.has(key)) return true;
    if (closedGroups.has(key)) return false;
    return !(g.paired && bothUp); // default: collapse only healthy pairs
  };
  const toggleGroup = (key: string, open: boolean) => {
    setOpenGroups((s) => {
      const n = new Set(s);
      if (open) n.delete(key);
      else n.add(key);
      return n;
    });
    setClosedGroups((s) => {
      const n = new Set(s);
      if (open) n.add(key);
      else n.delete(key);
      return n;
    });
  };

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

  const allTags = [...new Set((data?.tunnels ?? []).flatMap((t) => t.tags ?? []))].sort();
  const filtered = (data?.tunnels ?? []).filter((t) => {
    const matchSearch =
      t.instance_name.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase()) ||
      t.remote.toLowerCase().includes(search.toLowerCase()) ||
      (t.tags ?? []).some((tag) => tag.toLowerCase().includes(search.toLowerCase()));
    const matchFilter =
      filter === "all" ||
      (filter === "up" && isUp(t.phase1_status)) ||
      (filter === "down" && !isUp(t.phase1_status));
    const matchTag = !activeTag || (t.tags ?? []).includes(activeTag);
    return matchSearch && matchFilter && matchTag;
  });

  const { sorted, sort, toggle: sortToggle } = useSort(filtered, VPN_ACCESSORS);
  const groups = buildGroups(filtered);
  const groupBothUp = (g: TunnelGroup) =>
    g.paired && pairHealth(g.members[0], g.members[1]).label === "both up";
  const anyCollapsed = groups.some((g) => g.paired && !isGroupOpen(g, groupKey(g), groupBothUp(g)));
  const toggleAll = () => {
    if (anyCollapsed) {
      setOpenGroups(new Set(groups.map(groupKey)));
      setClosedGroups(new Set());
    } else {
      setClosedGroups(new Set(groups.filter((g) => g.paired).map(groupKey)));
      setOpenGroups(new Set());
    }
  };
  const hasCollapsiblePairs = groups.some((g) => g.paired);

  const renderRow = (t: GlobalTunnel, inGroup: boolean) => {
    const up = isUp(t.phase1_status);
    const k = rowKey(t);
    const isOpen = expanded.has(k);
    const hasChildren = (t.children?.length ?? 0) > 0;
    return (
      <Fragment key={k}>
        <tr className={`border-t border-slate-800 ${inGroup ? "bg-emerald-500/10" : ""}`}>
          <td className={`px-3 py-2 ${inGroup ? "border-l-4 border-emerald-500" : ""}`}>
            <span className={`inline-flex items-center gap-1.5 ${inGroup ? "pl-4" : ""}`}>
              <Link
                to={`/instances/${t.instance_id}`}
                className="text-emerald-400 hover:underline"
              >
                {t.instance_name}
              </Link>
              <WebUiIconLink
                instanceId={t.instance_id}
                instanceName={t.instance_name}
                agentMode={t.agent_mode ?? false}
              />
            </span>
          </td>
          <td className="px-3 py-2">
            <button
              onClick={() => toggleExpand(k)}
              disabled={!hasChildren}
              className="inline-flex items-center gap-1 text-left hover:text-emerald-400 disabled:opacity-40"
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
            <span
              className={`inline-flex items-center gap-1 ${
                t.stale ? "text-slate-400" : up ? "text-emerald-400" : "text-red-400"
              }`}
              title={t.stale ? "Agent silent — last-known status, not live" : undefined}
            >
              {up ? <Link2 className="h-3 w-3" /> : <Unlink className="h-3 w-3" />}
              {t.phase1_status}
            </span>
            {t.stale && <StaleChip seconds={t.stale_seconds} />}
          </td>
          <td className="whitespace-nowrap px-3 py-2">
            <div className="flex items-center gap-2">
              <Phase2Badge up={t.phase2_up} total={t.phase2_total} />
              <PingSummary entries={t.children ?? []} />
              <Phase2DupNote entries={t.children ?? []} />
            </div>
          </td>
          <td className="px-3 py-2 font-mono text-xs text-slate-400">
            {up && t.seconds_established > 0 ? fmtDuration(t.seconds_established) : "—"}
          </td>
          <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes_in)}</td>
          <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes_out)}</td>
          <td className="px-3 py-2">
            <div className="flex items-center justify-end gap-1">
              <button
                onClick={() => setHistoryTarget(t)}
                title="State-change history"
                className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              >
                <History className="h-3 w-3" /> History
              </button>
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
                <RotateCw className={`h-3 w-3 ${pending.has(rowKey(t)) ? "animate-spin" : ""}`} />{" "}
                Reconnect
              </button>
            </div>
          </td>
        </tr>
        {isOpen && (
          <tr
            className={`border-t border-slate-800/50 ${inGroup ? "bg-emerald-500/10" : "bg-slate-900/40"}`}
          >
            <td
              colSpan={9}
              className={`px-3 py-1 ${inGroup ? "border-l-4 border-emerald-500" : ""}`}
            >
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
  };

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
        <button
          onClick={() => setGroupedPersisted(!grouped)}
          title="Group the two ends of each tunnel together"
          className={`ml-auto inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-xs ${
            grouped ? "bg-emerald-600 text-white" : "text-slate-400 hover:bg-slate-800"
          }`}
        >
          <Link2 className="h-3 w-3" /> {grouped ? "Grouped" : "Flat"}
        </button>
        {grouped && hasCollapsiblePairs && (
          <button
            onClick={toggleAll}
            className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-xs text-slate-400 hover:bg-slate-800"
          >
            {anyCollapsed ? (
              <>
                <ChevronDown className="h-3 w-3" /> Expand all
              </>
            ) : (
              <>
                <ChevronRight className="h-3 w-3" /> Collapse all
              </>
            )}
          </button>
        )}
      </div>

      {/* Tag filter chips (mirrors the Instances list) */}
      {allTags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            onClick={() => setActiveTag(null)}
            className={`rounded-full px-3 py-1 text-xs ${
              !activeTag
                ? "bg-emerald-600 text-white"
                : "bg-slate-800 text-slate-400 hover:bg-slate-700"
            }`}
          >
            All
          </button>
          {allTags.map((tag) => (
            <button
              key={tag}
              onClick={() => setActiveTag(activeTag === tag ? null : tag)}
              className={`rounded-full px-3 py-1 text-xs ${
                activeTag === tag
                  ? "bg-emerald-600 text-white"
                  : "bg-slate-800 text-slate-400 hover:bg-slate-700"
              }`}
            >
              {tag}
            </button>
          ))}
        </div>
      )}

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
          <table className="w-full min-w-[1080px] text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                {grouped ? (
                  <>
                    <th className="px-3 py-2">Instance</th>
                    <th className="px-3 py-2">Tunnel</th>
                    <th className="px-3 py-2">Remote</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Phase 2</th>
                    <th className="px-3 py-2">Uptime</th>
                    <th className="px-3 py-2 text-right">IN</th>
                    <th className="px-3 py-2 text-right">OUT</th>
                  </>
                ) : (
                  <>
                    <SortHeader
                      label="Instance"
                      colKey="instance"
                      sort={sort}
                      toggle={sortToggle}
                    />
                    <SortHeader label="Tunnel" colKey="tunnel" sort={sort} toggle={sortToggle} />
                    <SortHeader label="Remote" colKey="remote" sort={sort} toggle={sortToggle} />
                    <SortHeader label="Status" colKey="status" sort={sort} toggle={sortToggle} />
                    <SortHeader label="Phase 2" colKey="phase2" sort={sort} toggle={sortToggle} />
                    <SortHeader label="Uptime" colKey="uptime" sort={sort} toggle={sortToggle} />
                    <SortHeader
                      label="IN"
                      colKey="in"
                      sort={sort}
                      toggle={sortToggle}
                      align="right"
                      className="text-right"
                    />
                    <SortHeader
                      label="OUT"
                      colKey="out"
                      sort={sort}
                      toggle={sortToggle}
                      align="right"
                      className="text-right"
                    />
                  </>
                )}
                <th className="px-3 py-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {grouped
                ? groups.map((group, gi) => {
                    const [a, b] = group.members;
                    const h = group.paired ? pairHealth(a, b) : null;
                    const bothUp = !!h && h.label === "both up";
                    const gkey = groupKey(group);
                    const open = isGroupOpen(group, gkey, bothUp);
                    const linkUptime = group.paired
                      ? Math.max(a.seconds_established, b.seconds_established)
                      : 0;
                    return (
                      <Fragment key={`grp-${gi}`}>
                        {group.paired && h && (
                          <tr
                            className="cursor-pointer border-t border-slate-700 bg-slate-900/70 hover:bg-slate-900"
                            onClick={() => toggleGroup(gkey, open)}
                          >
                            <td
                              colSpan={9}
                              className={`px-3 py-1.5 text-xs ${open ? "border-l-4 border-emerald-500" : ""}`}
                            >
                              <span className="inline-flex flex-wrap items-center gap-2 text-slate-300">
                                {open ? (
                                  <ChevronDown className="h-3 w-3 text-slate-500" />
                                ) : (
                                  <ChevronRight className="h-3 w-3 text-slate-500" />
                                )}
                                <Link2 className="h-3 w-3 text-slate-500" />
                                <span className="font-medium">
                                  {a.instance_name} ⇄ {b.instance_name}
                                </span>
                                <span className="font-mono text-slate-500">
                                  {a.local || "?"} ↔ {a.remote || "?"}
                                </span>
                                <span className={`rounded px-1.5 py-0.5 ${h.cls}`}>{h.label}</span>
                                {linkUptime > 0 && (
                                  <span className="font-mono text-slate-500">
                                    up {fmtDuration(linkUptime)}
                                  </span>
                                )}
                                {!open && (
                                  <span className="text-slate-600">· expand to view ends</span>
                                )}
                              </span>
                            </td>
                          </tr>
                        )}
                        {open && group.members.map((t) => renderRow(t, group.paired))}
                      </Fragment>
                    );
                  })
                : sorted.map((t) => renderRow(t, false))}
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

      {historyTarget && (
        <TunnelHistoryDialog
          instanceId={historyTarget.instance_id}
          tunnelId={historyTarget.tunnel_id}
          tunnelDescription={historyTarget.description || historyTarget.tunnel_id}
          onClose={() => setHistoryTarget(null)}
        />
      )}
    </div>
  );
}

/** Amber "agent silent" marker shown next to a tunnel whose owning instance is stale. */
function StaleChip({ seconds }: { seconds?: number | null }) {
  const age = seconds != null ? ` ${fmtDuration(seconds)}` : "";
  return (
    <span
      className="ml-2 inline-flex items-center gap-1 rounded bg-amber-600/20 px-1.5 py-0.5 text-xs text-amber-400"
      title="The owning instance's agent has gone silent — this value is the last push, not live."
    >
      stale · agent silent{age}
    </span>
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
