import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, RefreshCw, ExternalLink, Download, Pencil, Power } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import type { Instance, SystemStatus } from "../lib/types";

interface AgentStatus {
  agent_connected: boolean;
  gui_proxy_enabled?: boolean;
  platform?: string;
}

interface Props {
  instance: Instance | undefined;
  status: SystemStatus | undefined;
  fallbackId: string | undefined;
  onRefresh: () => void;
  onEdit: () => void;
}

function statusPill(inst: Instance | undefined) {
  if (!inst) return { label: "Unknown", dot: "bg-slate-500", text: "text-slate-400" };
  if (inst.last_error_at && !inst.last_success_at)
    return { label: "Offline", dot: "bg-red-500", text: "text-red-400" };
  if (inst.last_error_at && inst.last_success_at && inst.last_error_at > inst.last_success_at)
    return { label: "Degraded", dot: "bg-amber-500", text: "text-amber-400" };
  if (inst.last_success_at)
    return { label: "Online", dot: "bg-emerald-500", text: "text-emerald-400" };
  return { label: "Unknown", dot: "bg-slate-500", text: "text-slate-400" };
}

export default function InstanceHeader({ instance, status, fallbackId, onRefresh, onEdit }: Props) {
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [rebootOpen, setRebootOpen] = useState(false);
  const id = instance?.id ?? Number(fallbackId);
  const agentMode = instance?.agent_mode ?? false;

  const flash = (m: { ok: boolean; text: string }) => {
    setMsg(m);
    setTimeout(() => setMsg(null), 5000);
  };

  // Shares the React Query cache key with AgentSection — no extra request.
  const { data: agent } = useQuery({
    queryKey: ["agent-status", id],
    queryFn: () => api.get<AgentStatus>(`/api/instances/${id}/agent/status`),
    refetchInterval: 10_000,
    enabled: agentMode && Number.isFinite(id),
  });

  const guiMut = useMutation({
    mutationFn: () => api.post<{ url: string }>(`/api/instances/${id}/gui/open`),
    onSuccess: (data) => window.open(data.url, "_blank", "noopener,noreferrer"),
    onError: (e) =>
      flash({ ok: false, text: apiErrorText(e, "Could not open GUI") }),
  });

  const pill = statusPill(instance);
  const platform = agent?.platform?.trim();
  const version = status?.version?.trim();
  const showGui = agentMode && agent?.gui_proxy_enabled && agent?.agent_connected;

  const btn =
    "flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50";

  return (
    <div>
      {/* Identity row */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Link to="/" className="text-slate-500 hover:text-slate-300" aria-label="Back to instances">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <h1 className="text-xl font-semibold">{instance?.name ?? `Instance ${fallbackId}`}</h1>
        <span className={`inline-flex items-center gap-1.5 text-xs ${pill.text}`}>
          <span className={`h-2 w-2 rounded-full ${pill.dot}`} />
          {pill.label}
        </span>
        {(platform || version) && (
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">
            {[platform, version].filter(Boolean).join(" ")}
          </span>
        )}
        {instance?.base_url
          ?.split(",")
          .map((u) => u.trim())
          .filter(Boolean)
          .map((url) => (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noreferrer"
              className="font-mono text-xs text-slate-500 hover:text-slate-300 hover:underline"
            >
              {url}
            </a>
          ))}
        {instance?.location && (
          <span className="text-xs text-slate-500">· {instance.location}</span>
        )}
        {instance?.tags?.map((t) => (
          <span key={t} className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
            {t}
          </span>
        ))}
      </div>

      {/* Action bar */}
      <div className="mt-3 flex flex-wrap items-center gap-2 border-y border-slate-800 py-2">
        {showGui && (
          <button
            onClick={() => guiMut.mutate()}
            disabled={guiMut.isPending}
            className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            {guiMut.isPending ? "Opening…" : "Open GUI"}
          </button>
        )}
        <button onClick={onRefresh} className={btn}>
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
        <button
          onClick={() => window.open(`/api/instances/${id}/config-backup`, "_blank")}
          className={btn}
        >
          <Download className="h-3.5 w-3.5" /> Config Backup
        </button>
        <button onClick={onEdit} className={btn}>
          <Pencil className="h-3.5 w-3.5" /> Edit
        </button>
        <button
          onClick={() => setRebootOpen(true)}
          className="ml-auto flex items-center gap-1.5 rounded-lg border border-red-800/50 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/20"
        >
          <Power className="h-3.5 w-3.5" /> Reboot
        </button>
      </div>

      {msg && (
        <div
          className={`mt-2 rounded-lg px-3 py-2 text-sm ${
            msg.ok ? "bg-emerald-900/40 text-emerald-300" : "bg-red-900/40 text-red-300"
          }`}
        >
          {msg.text}
        </div>
      )}

      {rebootOpen && (
        <RebootDialog
          instanceId={id}
          instanceName={instance?.name ?? ""}
          onClose={() => setRebootOpen(false)}
          onResult={flash}
        />
      )}
    </div>
  );
}

function RebootDialog({
  instanceId,
  instanceName,
  onClose,
  onResult,
}: {
  instanceId: number;
  instanceName: string;
  onClose: () => void;
  onResult: (m: { ok: boolean; text: string }) => void;
}) {
  const [confirmName, setConfirmName] = useState("");
  const rebootMut = useMutation({
    mutationFn: () =>
      api.post<{ success: boolean; message: string }>(`/api/instances/${instanceId}/reboot`),
    onSuccess: () => {
      onResult({ ok: true, text: "Reboot triggered." });
      onClose();
    },
    onError: (e) => {
      onResult({ ok: false, text: apiErrorText(e, "Error") });
      onClose();
    },
  });

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-xl border border-red-800/50 bg-slate-900 p-5 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="flex items-center gap-2 text-sm font-semibold text-red-300">
          <Power className="h-4 w-4" /> Reboot firewall
        </h3>
        <p className="mt-2 text-sm text-slate-400">
          This restarts the firewall and drops all connections. Type the instance name{" "}
          <span className="font-mono text-slate-300">{instanceName}</span> to confirm.
        </p>
        <input
          value={confirmName}
          onChange={(e) => setConfirmName(e.target.value)}
          placeholder={instanceName}
          autoFocus
          className="mt-3 w-full rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-red-600 focus:outline-none"
        />
        <div className="mt-4 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-lg px-3 py-1.5 text-sm text-slate-400 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            onClick={() => rebootMut.mutate()}
            disabled={confirmName !== instanceName || rebootMut.isPending}
            className="rounded-lg bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50"
          >
            {rebootMut.isPending ? "Rebooting…" : "Reboot now"}
          </button>
        </div>
      </div>
    </div>
  );
}
