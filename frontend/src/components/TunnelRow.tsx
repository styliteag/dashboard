import { Fragment } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Link2,
  Unlink,
  RotateCw,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  History,
  LineChart,
} from "lucide-react";
import { api } from "../lib/api";
import type { IPsecChild, IPsecPingMonitor } from "../lib/types";
import {
  LipMismatchNote,
  Phase2Badge,
  Phase2ChildList,
  Phase2DupNote,
  PingSummary,
} from "./IPsecPhase2";
import { WebUiIconLink } from "./WebUiIconLink";
import { ShellIconLink } from "./ShellIconLink";
import { useShellEnabledMap } from "../lib/instances";
import { ipsecDirectUrl, ipsecUiPath, isUp, rowKey, type GlobalTunnel } from "../lib/vpn-overview";
import { fmtBytes, fmtDuration } from "../lib/format";

export interface DialogTarget {
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

/** One tunnel end as a table row, plus its expandable Phase-2 detail row. */
export default function TunnelRow({
  tunnel: t,
  inGroup,
  expanded,
  busy,
  onToggleExpand,
  onRecheck,
  onReconnect,
  onHistory,
  onGraph,
  onConfigure,
}: {
  tunnel: GlobalTunnel;
  inGroup: boolean;
  expanded: boolean;
  busy: boolean;
  onToggleExpand: (key: string) => void;
  onRecheck: (tunnel: GlobalTunnel) => void;
  onReconnect: (tunnel: GlobalTunnel) => void;
  onHistory: (tunnel: GlobalTunnel) => void;
  onGraph: (tunnel: GlobalTunnel) => void;
  onConfigure: (target: DialogTarget) => void;
}) {
  const up = isUp(t.phase1_status);
  const k = rowKey(t);
  const hasChildren = (t.children?.length ?? 0) > 0;
  const shellEnabled = useShellEnabledMap().get(t.instance_id) ?? false;
  return (
    <Fragment>
      <tr className={`border-t border-slate-800 ${inGroup ? "bg-emerald-500/10" : ""}`}>
        <td className={`px-3 py-2 ${inGroup ? "border-l-4 border-emerald-500" : ""}`}>
          <span className={`inline-flex items-center gap-1.5 ${inGroup ? "pl-4" : ""}`}>
            <Link to={`/instances/${t.instance_id}`} className="text-emerald-400 hover:underline">
              {t.instance_name}
            </Link>
            <WebUiIconLink
              instanceId={t.instance_id}
              instanceName={t.instance_name}
              agentMode={t.agent_mode ?? false}
              path={ipsecUiPath(t.device_type) || undefined}
              directUrl={ipsecDirectUrl(t)}
              title={`Open IPsec status on ${t.instance_name}`}
            />
            <ShellIconLink
              instanceId={t.instance_id}
              instanceName={t.instance_name}
              eligible={t.agent_mode ?? false}
              shellEnabled={shellEnabled}
            />
          </span>
        </td>
        <td className="px-3 py-2">
          <button
            onClick={() => onToggleExpand(k)}
            disabled={!hasChildren}
            className="inline-flex items-center gap-1 text-left hover:text-emerald-400 disabled:opacity-40"
          >
            {hasChildren ? (
              expanded ? (
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
        <td className="hidden px-3 py-2 font-mono text-xs xl:table-cell">{t.remote}</td>
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
            <LipMismatchNote local={t.local} mismatch={t.local_ip_mismatch} />
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
              onClick={() => onRecheck(t)}
              disabled={busy}
              title="Re-check this connection now (no 30s wait)"
              className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200 disabled:opacity-50"
            >
              <RefreshCw className={`h-3 w-3 ${busy ? "animate-spin" : ""}`} /> Recheck
            </button>
            <button
              onClick={() => onHistory(t)}
              title="State-change history"
              className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            >
              <History className="h-3 w-3" /> History
            </button>
            <button
              onClick={() => onGraph(t)}
              title="Up/down timeline"
              className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            >
              <LineChart className="h-3 w-3" /> Graph
            </button>
            <button
              onClick={() => onReconnect(t)}
              disabled={busy}
              className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-emerald-400 hover:bg-slate-800 disabled:opacity-50"
            >
              <RotateCw className={`h-3 w-3 ${busy ? "animate-spin" : ""}`} /> Reconnect
            </button>
          </div>
        </td>
      </tr>
      {expanded && (
        <tr
          className={`border-t border-slate-800/50 ${inGroup ? "bg-emerald-500/10" : "bg-slate-900/40"}`}
        >
          <td colSpan={9} className={`px-3 py-1 ${inGroup ? "border-l-4 border-emerald-500" : ""}`}>
            <ExpandedPhase2
              tunnel={t}
              onConfigure={(tn, child, existing) =>
                onConfigure({
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
}
