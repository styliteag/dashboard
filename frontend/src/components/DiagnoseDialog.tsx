/**
 * Tunnel diagnostics: pulls swanctl config + live SAs + the recent IPsec log +
 * a peer-reachability ping over SSH and shows them readable. "Copy all" yields a
 * paste-ready bundle (the user's ChatGPT workflow); an LLM "Analyse" button can
 * sit next to it later.
 */
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ClipboardCopy, Check } from "lucide-react";
import { api } from "../lib/api";
import type { IPsecDiagnosis } from "../lib/types";
import Dialog from "./Dialog";

interface Props {
  instanceId: number;
  tunnelId: string;
  tunnelName: string;
  onClose: () => void;
}

function bundleText(d: IPsecDiagnosis): string {
  return d.sections.map((s) => `### ${s.title}\n${s.content || "(empty)"}`).join("\n\n");
}

export default function DiagnoseDialog({ instanceId, tunnelId, tunnelName, onClose }: Props) {
  const [copied, setCopied] = useState(false);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["ipsec-diagnose", instanceId, tunnelId],
    queryFn: () =>
      api.get<IPsecDiagnosis>(
        `/api/instances/${instanceId}/ipsec/${encodeURIComponent(tunnelId)}/diagnose`,
      ),
    refetchOnWindowFocus: false,
    staleTime: 0,
  });

  const copyAll = async () => {
    if (!data) return;
    await navigator.clipboard.writeText(bundleText(data));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Dialog title={`Diagnose tunnel: ${tunnelName}`} onClose={onClose} wide>
      {isLoading && (
        <p className="text-sm text-slate-400">Gathering diagnostics over SSH (config, SAs, log, ping)…</p>
      )}
      {isError && <p className="text-sm text-red-400">Could not gather diagnostics.</p>}
      {data && (
        <div className="space-y-3">
          <div className="flex justify-end">
            <button
              onClick={copyAll}
              className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
            >
              {copied ? <Check className="h-3 w-3" /> : <ClipboardCopy className="h-3 w-3" />}
              {copied ? "Copied" : "Copy all"}
            </button>
          </div>
          {data.sections.map((s) => (
            <div key={s.title} className="space-y-1">
              <h3 className="text-xs font-semibold text-slate-300">{s.title}</h3>
              <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded border border-slate-800 bg-slate-900 p-2 font-mono text-[11px] leading-relaxed text-slate-300">
                {s.content || "(empty)"}
              </pre>
            </div>
          ))}
        </div>
      )}
    </Dialog>
  );
}
