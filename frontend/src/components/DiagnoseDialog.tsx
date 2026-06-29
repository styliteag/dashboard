/**
 * Tunnel diagnostics: pulls swanctl config + live SAs + the recent IPsec log +
 * a peer-reachability ping over SSH and shows them readable. "Copy all" yields a
 * paste-ready bundle; the "Analyse with AI" control sends the same bundle to a
 * configured LLM (anonymized server-side) and shows the findings inline.
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Bot, Check, ClipboardCopy, Eye, Loader2, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { IPsecDiagnosis } from "../lib/types";
import Dialog from "./Dialog";

interface Props {
  instanceId: number;
  tunnelId: string;
  tunnelName: string;
  onClose: () => void;
}

interface LlmProvider {
  id: string;
  label: string;
  configured: boolean;
}
interface AnalyzeResponse {
  ok: boolean;
  provider: string;
  model: string;
  findings: string;
  sent_chars: number;
  error: string | null;
}

function bundleText(d: IPsecDiagnosis): string {
  return d.sections.map((s) => `### ${s.title}\n${s.content || "(empty)"}`).join("\n\n");
}

export default function DiagnoseDialog({ instanceId, tunnelId, tunnelName, onClose }: Props) {
  const [copied, setCopied] = useState(false);
  const [provider, setProvider] = useState("");
  const [showPreview, setShowPreview] = useState(false);
  const [preview, setPreview] = useState("");
  const [result, setResult] = useState<AnalyzeResponse | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["ipsec-diagnose", instanceId, tunnelId],
    queryFn: () =>
      api.get<IPsecDiagnosis>(
        `/api/instances/${instanceId}/ipsec/${encodeURIComponent(tunnelId)}/diagnose`,
      ),
    refetchOnWindowFocus: false,
    staleTime: 0,
  });

  const { data: providers = [] } = useQuery({
    queryKey: ["llm-providers"],
    queryFn: () => api.get<LlmProvider[]>("/api/llm/providers"),
  });
  const configured = providers.filter((p) => p.configured);
  useEffect(() => {
    if (!provider && configured.length) setProvider(configured[0].id);
  }, [provider, configured]);

  const previewMut = useMutation({
    mutationFn: () =>
      api.post<{ anonymized: string }>("/api/llm/preview", { text: data ? bundleText(data) : "" }),
    onSuccess: (r) => {
      setPreview(r.anonymized);
      setShowPreview(true);
    },
  });

  const analyzeMut = useMutation({
    mutationFn: () =>
      api.post<AnalyzeResponse>("/api/llm/analyze", {
        provider,
        text: data ? bundleText(data) : "",
      }),
    onSuccess: (r) => setResult(r),
    onError: (e) =>
      setResult({
        ok: false,
        provider,
        model: "",
        findings: "",
        sent_chars: 0,
        error: e instanceof ApiError ? e.message : "Analysis failed",
      }),
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
        <p className="text-sm text-slate-400">
          Gathering diagnostics over SSH (config, SAs, log, ping)…
        </p>
      )}
      {isError && <p className="text-sm text-red-400">Could not gather diagnostics.</p>}
      {data && (
        <div className="space-y-3">
          {/* Toolbar: AI analysis (left) + copy (right) */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-100"
              >
                {configured.length === 0 && <option value="">No provider key set</option>}
                {configured.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </select>
              <button
                onClick={() => analyzeMut.mutate()}
                disabled={!provider || analyzeMut.isPending}
                className="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
              >
                {analyzeMut.isPending ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Bot className="h-3 w-3" />
                )}
                {analyzeMut.isPending ? "Analyzing…" : "Analyse with AI"}
              </button>
              <button
                onClick={() => (showPreview ? setShowPreview(false) : previewMut.mutate())}
                className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
              >
                <Eye className="h-3 w-3" /> {showPreview ? "Hide" : "Preview"} sent data
              </button>
            </div>
            <button
              onClick={copyAll}
              className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
            >
              {copied ? <Check className="h-3 w-3" /> : <ClipboardCopy className="h-3 w-3" />}
              {copied ? "Copied" : "Copy all"}
            </button>
          </div>

          <p className="flex items-center gap-1.5 text-[11px] text-slate-500">
            <ShieldCheck className="h-3 w-3 text-emerald-500" />
            Sent anonymized: internal IPs kept; public IPs, MAC vendors, hostnames and secrets
            scrubbed.
          </p>

          {showPreview && (
            <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all rounded border border-slate-800 bg-slate-950 p-2 font-mono text-[11px] text-slate-300">
              {preview || "…"}
            </pre>
          )}

          {result && (
            <div className="rounded border border-slate-800 bg-slate-900/60 p-2">
              {result.ok ? (
                <>
                  <p className="mb-1 text-[11px] text-slate-500">
                    {result.provider} · {result.model} · {result.sent_chars} chars sent
                  </p>
                  <pre className="max-h-96 overflow-auto whitespace-pre-wrap text-xs text-slate-200">
                    {result.findings}
                  </pre>
                </>
              ) : (
                <p className="text-xs text-red-400">{result.error}</p>
              )}
            </div>
          )}

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
