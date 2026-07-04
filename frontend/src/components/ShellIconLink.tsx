import { SquareTerminal } from "lucide-react";

/**
 * Small icon-only button that opens an instance's browser terminal (root shell
 * over the agent WS) in a new tab, for use next to the WebGUI icon in list views.
 * Renders only for agent-mode boxes that have the terminal opted in per instance
 * (Edit instance → "Terminal"). The server-wide DASH_SHELL_ENABLED gate and group
 * scope are enforced on the WS; `stopPropagation` keeps the click off the row.
 */
export function ShellIconLink({
  instanceId,
  instanceName,
  agentMode,
  shellEnabled,
  title,
  className = "",
  iconClassName = "h-3.5 w-3.5",
}: {
  instanceId: number;
  instanceName?: string;
  agentMode: boolean;
  shellEnabled: boolean;
  title?: string;
  className?: string;
  iconClassName?: string;
}) {
  if (!agentMode || !shellEnabled) return null;
  const label = title ?? `Open root terminal on ${instanceName ?? "instance"}`;
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        e.preventDefault();
        window.open(`/instances/${instanceId}/terminal`, "_blank", "noopener");
      }}
      title={label}
      aria-label={label}
      className={`inline-flex items-center rounded p-0.5 text-amber-400/80 hover:bg-slate-800 hover:text-amber-300 ${className}`}
    >
      <SquareTerminal className={iconClassName} />
    </button>
  );
}
