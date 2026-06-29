import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Bot, ChevronDown, ChevronUp, Eye, Loader2, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../lib/api";
import Markdown from "./Markdown";

interface LogfileItem {
  name: string;
  collected_at: string;
  bytes: number;
}
interface LlmProvider {
  id: string;
  label: string;
  configured: boolean;
}
interface AnonymizedLogs {
  text: string;
  names: string[];
}
interface AnalyzeResponse {
  ok: boolean;
  provider: string;
  model: string;
  findings: string;
  sent_chars: number;
  error: string | null;
}

function fmtBytes(n: number): string {
  return n >= 1024 ? `${(n / 1024).toFixed(0)} KB` : `${n} B`;
}

/**
 * AI log analysis: shows the agent's stored log snapshots, lets the admin preview
 * exactly what (anonymized) text would be sent, pick a configured provider, and
 * run the analysis. Raw log content never reaches the browser — the backend only
 * serves the anonymized text.
 */
export default function AiLogAnalysisSection({ instanceId }: { instanceId: number }) {
  const [expanded, setExpanded] = useState(false);
  const [provider, setProvider] = useState("");
  const [showPreview, setShowPreview] = useState(false);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);

  const { data: logs = [] } = useQuery({
    queryKey: ["instance-logs", instanceId],
    queryFn: () => api.get<LogfileItem[]>(`/api/instances/${instanceId}/logs`),
    enabled: expanded,
  });

  const { data: providers = [] } = useQuery({
    queryKey: ["llm-providers"],
    queryFn: () => api.get<LlmProvider[]>("/api/llm/providers"),
    enabled: expanded,
  });

  const { data: anon } = useQuery({
    queryKey: ["instance-logs-anon", instanceId],
    queryFn: () => api.get<AnonymizedLogs>(`/api/instances/${instanceId}/logs/anonymized`),
    enabled: expanded,
  });

  // Default the provider picker to the first configured one ("ask each time").
  const configured = providers.filter((p) => p.configured);
  useEffect(() => {
    if (!provider && configured.length) setProvider(configured[0].id);
  }, [provider, configured]);

  const analyzeMut = useMutation({
    mutationFn: () =>
      api.post<AnalyzeResponse>("/api/llm/analyze", { provider, text: anon?.text ?? "" }),
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

  const hasLogs = logs.length > 0;
  const canAnalyze = hasLogs && !!provider && !!anon?.text && !analyzeMut.isPending;

  return (
    <section className="mt-8">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-2 text-sm font-semibold text-slate-400 hover:text-slate-200"
      >
        <Bot className="h-4 w-4" /> AI Log Analysis
        {expanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </button>

      {expanded && (
        <div className="mt-3 space-y-4 rounded-lg border border-slate-800 p-4">
          {!hasLogs ? (
            <p className="text-sm text-slate-500">
              No log snapshots yet — the agent collects important logs hourly. They appear here once
              the next collection runs.
            </p>
          ) : (
            <>
              {/* Stored snapshots */}
              <div className="flex flex-wrap gap-2">
                {logs.map((l) => (
                  <span
                    key={`${l.name}-${l.collected_at}`}
                    className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300"
                  >
                    {l.name} · {new Date(l.collected_at).toLocaleString()} · {fmtBytes(l.bytes)}
                  </span>
                ))}
              </div>

              {/* Controls */}
              <div className="flex flex-wrap items-center gap-2">
                <label className="text-xs font-medium text-slate-400">Provider</label>
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-sm text-slate-100"
                >
                  {configured.length === 0 && <option value="">No provider key set</option>}
                  {configured.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() => setShowPreview((v) => !v)}
                  className="flex items-center gap-1.5 rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-slate-100 hover:bg-slate-600"
                >
                  <Eye className="h-3.5 w-3.5" /> {showPreview ? "Hide" : "Preview"} sent data
                </button>
                <button
                  type="button"
                  onClick={() => analyzeMut.mutate()}
                  disabled={!canAnalyze}
                  className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
                >
                  {analyzeMut.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Bot className="h-3.5 w-3.5" />
                  )}
                  {analyzeMut.isPending ? "Analyzing…" : "Analyze with AI"}
                </button>
              </div>

              <p className="flex items-center gap-1.5 text-xs text-slate-500">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
                Anonymized log text is sent to the selected provider. Internal IPs are kept; public
                IPs, MAC vendors, hostnames and secrets are scrubbed. Use “Preview” to see exactly
                what leaves the box.
              </p>

              {showPreview && (
                <pre className="max-h-72 overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-3 text-[11px] leading-relaxed text-slate-300">
                  {anon?.text || "…"}
                </pre>
              )}

              {result && (
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  {result.ok ? (
                    <>
                      <p className="mb-2 text-xs text-slate-500">
                        {result.provider} · {result.model} · {result.sent_chars} chars sent
                      </p>
                      <div className="max-h-[28rem] overflow-auto pr-1">
                        <Markdown>{result.findings}</Markdown>
                      </div>
                    </>
                  ) : (
                    <p className="text-sm text-red-400">{result.error}</p>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </section>
  );
}
