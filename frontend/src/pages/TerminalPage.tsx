import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Terminal as TermIcon } from "lucide-react";
import { api } from "../lib/api";
import type { Instance } from "../lib/types";
import ShellTerminal, { type ShellStatus } from "../components/ShellTerminal";

/**
 * Full-page terminal, opened in its own browser tab from the instance header
 * (SPIKE, agent §22). Standalone route (no dashboard chrome) so several tabs can
 * hold several independent root shells to the same or different boxes.
 */
export default function TerminalPage() {
  const { id } = useParams<{ id: string }>();
  const instanceId = Number(id);
  const [status, setStatus] = useState<ShellStatus>("connecting");
  const [note, setNote] = useState<string | null>(null);

  const { data: instance } = useQuery({
    queryKey: ["instance", id],
    queryFn: () => api.get<Instance>(`/api/instances/${id}`),
    enabled: Number.isFinite(instanceId),
  });
  const name = instance?.name ?? `Instance ${id}`;

  useEffect(() => {
    document.title = `Terminal — ${name}`;
  }, [name]);

  const onStatus = useCallback((s: ShellStatus, n?: string) => {
    setStatus(s);
    if (n) setNote(n);
  }, []);

  const dot =
    status === "open"
      ? "text-emerald-400"
      : status === "connecting"
        ? "text-amber-400"
        : "text-slate-500";

  return (
    <div className="flex h-screen flex-col bg-[#0f172a] text-slate-200">
      <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-900 px-4 py-2">
        <TermIcon className="h-4 w-4 text-emerald-400" />
        <span className="text-sm font-medium">Terminal — {name}</span>
        <span className={`ml-2 inline-flex items-center gap-1 text-xs ${dot}`}>
          <span className="h-1.5 w-1.5 rounded-full bg-current" />
          {status}
        </span>
        <span className="ml-2 rounded bg-red-900/40 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-300">
          root
        </span>
        {note && <span className="ml-auto text-xs text-slate-400">{note}</span>}
      </div>
      <div className="min-h-0 flex-1 p-2">
        <ShellTerminal instanceId={instanceId} onStatus={onStatus} />
      </div>
    </div>
  );
}
