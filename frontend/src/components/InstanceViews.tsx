import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Wifi,
  WifiOff,
  AlertTriangle,
  Activity,
  ExternalLink,
  ArrowUpCircle,
} from "lucide-react";
import type { ConnectedAgent, Instance } from "../lib/types";
import TestConnectionButton from "./TestConnectionButton";

export interface InstanceViewProps {
  instance: Instance;
  agent?: ConnectedAgent;
  selected: boolean;
  onToggleSelect: () => void;
  onEdit: () => void;
  onDelete: () => void;
}

/** base_url may hold several comma-separated web-UI URLs; split + trim them. */
const splitUrls = (s: string): string[] => s.split(",").map((u) => u.trim()).filter(Boolean);

interface StatusMeta {
  icon: ReactNode;
  label: string;
  color: string;
}

/** Derive a connection status from the instance's last poll/error timestamps. */
function statusMeta(inst: Instance): StatusMeta {
  if (inst.last_error_at && !inst.last_success_at) {
    return { icon: <WifiOff className="h-4 w-4 text-red-400" />, label: "Offline", color: "text-red-400" };
  }
  if (inst.last_error_at && inst.last_success_at && inst.last_error_at > inst.last_success_at) {
    return {
      icon: <AlertTriangle className="h-4 w-4 text-amber-400" />,
      label: "Degraded",
      color: "text-amber-400",
    };
  }
  if (inst.last_success_at) {
    return { icon: <Wifi className="h-4 w-4 text-emerald-400" />, label: "Online", color: "text-emerald-400" };
  }
  return { icon: <WifiOff className="h-4 w-4 text-slate-500" />, label: "Unknown", color: "text-slate-500" };
}

function fmtTime(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString("en-US") : "—";
}

/** Push-mode platform + agent version (+ update indicator), or an "API" badge. */
function AgentBadge({ inst, agent }: { inst: Instance; agent?: ConnectedAgent }) {
  if (!inst.agent_mode) {
    return <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">API</span>;
  }
  if (!agent) {
    return <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-500">Agent · offline</span>;
  }
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="rounded bg-sky-900/40 px-1.5 py-0.5 text-xs capitalize text-sky-300">
        {agent.platform || "agent"}
      </span>
      <span className="font-mono text-xs text-slate-500">{agent.agent_version}</span>
      {agent.update_available && (
        <ArrowUpCircle className="h-3.5 w-3.5 text-amber-400" aria-label="Agent update available" />
      )}
    </span>
  );
}

function Tags({ tags }: { tags: string[] | null }) {
  if (!tags || tags.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map((t) => (
        <span key={t} className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
          {t}
        </span>
      ))}
    </div>
  );
}

/** Shared action cluster. The direct web-UI link is hidden for agent-mode
 *  instances — those boxes sit behind NAT and are reached via the GUI proxy
 *  ("Open GUI" on the detail page), so a raw base_url link would be dead. */
function InstanceActions({ instance: inst, onEdit, onDelete }: Omit<InstanceViewProps, "selected" | "onToggleSelect" | "agent">) {
  const linkCls =
    "flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200";
  return (
    <div className="flex items-center gap-1.5">
      {!inst.agent_mode &&
        splitUrls(inst.base_url).map((url) => (
          <a key={url} href={url} target="_blank" rel="noreferrer" title={`Open ${url}`} className={linkCls}>
            <ExternalLink className="h-3 w-3" />
          </a>
        ))}
      <TestConnectionButton instanceId={inst.id} />
      <Link to={`/instances/${inst.id}`} className={linkCls}>
        <Activity className="h-3 w-3" /> Details
      </Link>
      <button onClick={onEdit} className={linkCls}>
        Edit
      </button>
      <button
        onClick={onDelete}
        className="rounded-md px-2 py-1 text-xs text-red-400 hover:bg-slate-800 hover:text-red-300"
      >
        Delete
      </button>
    </div>
  );
}

export function InstanceCard({ instance: inst, agent, selected, onToggleSelect, onEdit, onDelete }: InstanceViewProps) {
  const status = statusMeta(inst);
  return (
    <div
      className={`rounded-xl border p-4 shadow ${
        selected ? "border-emerald-600 bg-emerald-900/10" : "border-slate-800 bg-slate-900/60"
      }`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <input type="checkbox" checked={selected} onChange={onToggleSelect} className="rounded border-slate-600" />
          {status.icon}
          <Link to={`/instances/${inst.id}`} className="font-medium hover:text-emerald-400">
            {inst.name}
          </Link>
        </div>
        <Tags tags={inst.tags} />
      </div>

      <div className="mt-2 flex items-center gap-2">
        <AgentBadge inst={inst} agent={agent} />
      </div>

      <div className="mt-2 flex flex-wrap gap-x-2 text-xs text-slate-500">
        {splitUrls(inst.base_url).map((url) => (
          <a
            key={url}
            href={url}
            target="_blank"
            rel="noreferrer"
            className="truncate hover:text-slate-300 hover:underline"
          >
            {url}
          </a>
        ))}
      </div>
      {inst.location && <p className="text-xs text-slate-500">{inst.location}</p>}

      {inst.last_error_message && <p className="mt-2 truncate text-xs text-red-400">{inst.last_error_message}</p>}

      <p className="mt-1 text-xs text-slate-600">Last poll: {fmtTime(inst.last_success_at)}</p>

      <div className="mt-3 border-t border-slate-800 pt-3">
        <InstanceActions instance={inst} onEdit={onEdit} onDelete={onDelete} />
      </div>
    </div>
  );
}

export function InstanceRow({ instance: inst, agent, selected, onToggleSelect, onEdit, onDelete }: InstanceViewProps) {
  const status = statusMeta(inst);
  return (
    <tr className={`border-t border-slate-800 ${selected ? "bg-emerald-900/10" : ""}`}>
      <td className="px-3 py-2">
        <input type="checkbox" checked={selected} onChange={onToggleSelect} className="rounded border-slate-600" />
      </td>
      <td className="px-3 py-2">
        <span className={`inline-flex items-center gap-1.5 ${status.color}`}>
          {status.icon}
          {status.label}
        </span>
      </td>
      <td className="px-3 py-2">
        <Link to={`/instances/${inst.id}`} className="font-medium text-slate-100 hover:text-emerald-400">
          {inst.name}
        </Link>
        {inst.last_error_message && (
          <p className="mt-0.5 max-w-xs truncate text-xs text-red-400">{inst.last_error_message}</p>
        )}
      </td>
      <td className="px-3 py-2 text-slate-400">{inst.location || "—"}</td>
      <td className="px-3 py-2">
        <AgentBadge inst={inst} agent={agent} />
      </td>
      <td className="px-3 py-2">
        <Tags tags={inst.tags} />
      </td>
      <td className="px-3 py-2 text-xs text-slate-500">{fmtTime(inst.last_success_at)}</td>
      <td className="px-3 py-2">
        <InstanceActions instance={inst} onEdit={onEdit} onDelete={onDelete} />
      </td>
    </tr>
  );
}
