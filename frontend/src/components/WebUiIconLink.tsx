import { useMutation } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { api, ApiError } from "../lib/api";

/**
 * Small icon-only link that opens an instance's WebGUI through the agent's
 * GUI-proxy tunnel (POST /gui/open → open the returned one-shot URL in a new tab),
 * for use in the global list views next to an instance name.
 *
 * `path` deep-links to a page inside the GUI (e.g. /ui/ipsec/sessions) instead of
 * the dashboard root. For non-agent boxes there is no tunnel to proxy through:
 * with `directUrl` set the icon becomes a plain link to the firewall's own web UI
 * (the firewall shows its login first, unless the browser has a session there);
 * without it, nothing renders. Errors (proxy disabled, agent offline) surface in
 * the tooltip and tint the icon red, mirroring the per-instance "WebUI" button.
 * `stopPropagation` keeps a click off the surrounding row link / row-level onClick.
 */
export function WebUiIconLink({
  instanceId,
  instanceName,
  agentMode,
  path,
  directUrl,
  title,
  className = "",
  iconClassName = "h-3.5 w-3.5",
}: {
  instanceId: number;
  instanceName?: string;
  agentMode: boolean;
  path?: string;
  directUrl?: string;
  title?: string;
  className?: string;
  iconClassName?: string;
}) {
  const guiMut = useMutation({
    mutationFn: () =>
      api.post<{ url: string }>(
        `/api/instances/${instanceId}/gui/open${path ? `?path=${encodeURIComponent(path)}` : ""}`,
      ),
    onSuccess: (r) => window.open(r.url, "_blank", "noopener,noreferrer"),
  });
  if (!agentMode) {
    if (!directUrl) return null;
    const directLabel = title ?? `Open ${instanceName ?? "instance"} WebGUI`;
    return (
      <a
        href={directUrl}
        target="_blank"
        rel="noopener noreferrer"
        onClick={(e) => e.stopPropagation()}
        title={`${directLabel} (direct — the firewall may ask you to log in)`}
        aria-label={directLabel}
        className={`inline-flex items-center rounded p-0.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 ${className}`}
      >
        <ExternalLink className={iconClassName} />
      </a>
    );
  }
  const err = guiMut.error instanceof ApiError ? guiMut.error.message : null;
  const label = title ?? `Open ${instanceName ?? "instance"} WebGUI (tunneled)`;
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
      <ExternalLink className={iconClassName} />
    </button>
  );
}
