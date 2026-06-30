import { useMutation } from "@tanstack/react-query";
import { Globe } from "lucide-react";
import { api, ApiError } from "../lib/api";

/**
 * Small icon-only link that opens an instance's WebGUI through the agent's
 * GUI-proxy tunnel (POST /gui/open → open the returned one-shot URL in a new tab),
 * for use in the global list views next to an instance name.
 *
 * Renders nothing for non-agent boxes — there is no tunnel to proxy through.
 * Errors (proxy disabled, agent offline) surface in the tooltip and tint the
 * icon red, mirroring the per-instance "WebUI" button. `stopPropagation` keeps a
 * click off the surrounding row link / row-level onClick.
 */
export function WebUiIconLink({
  instanceId,
  instanceName,
  agentMode,
  className = "",
}: {
  instanceId: number;
  instanceName?: string;
  agentMode: boolean;
  className?: string;
}) {
  const guiMut = useMutation({
    mutationFn: () => api.post<{ url: string }>(`/api/instances/${instanceId}/gui/open`),
    onSuccess: (r) => window.open(r.url, "_blank", "noopener,noreferrer"),
  });
  if (!agentMode) return null;
  const err = guiMut.error instanceof ApiError ? guiMut.error.message : null;
  const label = `Open ${instanceName ?? "instance"} WebGUI (tunneled)`;
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        e.preventDefault();
        guiMut.mutate();
      }}
      disabled={guiMut.isPending}
      title={err ?? label}
      aria-label={label}
      className={`inline-flex items-center rounded p-0.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 disabled:opacity-50 ${
        err ? "text-red-400" : ""
      } ${className}`}
    >
      <Globe className="h-3.5 w-3.5" />
    </button>
  );
}
