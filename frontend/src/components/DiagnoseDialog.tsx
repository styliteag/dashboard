/**
 * Tunnel diagnostics: pulls swanctl config + live SAs + the recent IPsec log +
 * a peer-reachability ping over SSH and shows them readable. "Copy all" yields a
 * paste-ready bundle; the "Analyse with AI" control sends the same bundle to a
 * configured LLM (anonymized server-side) and shows the findings inline.
 */
import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Bot, Check, ClipboardCopy, Eye, Loader2, ShieldCheck } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import type { IPsecDiagnosis } from "../lib/types";
import Dialog from "./Dialog";
import Markdown from "./Markdown";

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
  const [activeTab, setActiveTab] = useState(0);

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
        error: apiErrorText(e, "Analysis failed"),
      }),
  });

  const copyAll = async () => {
    if (!data) return;
    await navigator.clipboard.writeText(bundleText(data));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const active = data?.sections[Math.min(activeTab, (data.sections.length || 1) - 1)];

  return (
    <Dialog title={`Diagnose tunnel: ${tunnelName}`} onClose={onClose} size="2xl">
      {isLoading && (
        <p className="text-sm text-slate-400">
          Gathering diagnostics over SSH (config, SAs, log, ping)…
        </p>
      )}
      {isError && <p className="text-sm text-red-400">Could not gather diagnostics.</p>}
      {data && (
        <div className="flex min-h-0 flex-1 flex-col gap-3">
          {/* Toolbar: AI controls (left) + copy (right) */}
          <div className="flex shrink-0 flex-wrap items-center justify-between gap-2">
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
              <span className="flex items-center gap-1 text-[11px] text-slate-500">
                <ShieldCheck className="h-3 w-3 text-emerald-500" /> sent anonymized
              </span>
            </div>
            <button
              onClick={copyAll}
              className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
            >
              {copied ? <Check className="h-3 w-3" /> : <ClipboardCopy className="h-3 w-3" />}
              {copied ? "Copied" : "Copy all"}
            </button>
          </div>

          {showPreview && (
            <pre className="max-h-40 shrink-0 overflow-auto whitespace-pre-wrap break-all rounded border border-slate-800 bg-slate-950 p-2 font-mono text-[11px] text-slate-300">
              {preview || "…"}
            </pre>
          )}

          {/* Two columns: AI findings | raw diagnostic sections (tabbed) */}
          <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 md:grid-cols-2">
            {/* Left: AI analysis */}
            <div className="flex min-h-0 flex-col rounded-lg border border-emerald-900/40 bg-slate-900/40">
              <div className="flex shrink-0 items-center gap-1.5 border-b border-slate-800 px-3 py-2 text-xs font-semibold text-slate-300">
                <Bot className="h-3.5 w-3.5 text-emerald-500" /> AI analysis
                {result?.ok && (
                  <span className="ml-auto font-normal text-slate-500">
                    {result.model} · {result.sent_chars} chars
                  </span>
                )}
              </div>
              <div className="min-h-0 flex-1 overflow-auto p-3">
                {analyzeMut.isPending ? (
                  <p className="text-xs text-slate-500">Analyzing…</p>
                ) : result?.ok ? (
                  <Markdown>{result.findings}</Markdown>
                ) : result ? (
                  <p className="text-xs text-red-400">{result.error}</p>
                ) : (
                  <p className="text-xs text-slate-500">
                    Pick a provider and hit “Analyse with AI” to get findings on this tunnel.
                  </p>
                )}
              </div>
            </div>

            {/* Right: raw sections in tabs */}
            <div className="flex min-h-0 flex-col rounded-lg border border-slate-800 bg-slate-900/40">
              <div className="flex shrink-0 flex-wrap gap-1 border-b border-slate-800 px-2 py-1.5">
                {data.sections.map((s, i) => (
                  <button
                    key={s.title}
                    onClick={() => setActiveTab(i)}
                    className={`rounded px-2 py-1 text-[11px] ${
                      i === activeTab
                        ? "bg-slate-700 text-slate-100"
                        : "text-slate-400 hover:bg-slate-800"
                    }`}
                  >
                    {s.title.split("(")[0].trim()}
                  </button>
                ))}
              </div>
              <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-all p-3 font-mono text-[11px] leading-relaxed text-slate-300">
                {active?.content || "(empty)"}
              </pre>
            </div>
          </div>
        </div>
      )}
    </Dialog>
  );
}
