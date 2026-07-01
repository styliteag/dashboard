import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Bot, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { api, apiErrorText } from "../../lib/api";

interface LlmProvider {
  id: string;
  label: string;
  configured: boolean;
}

interface LlmTestResult {
  provider: string;
  configured: boolean;
  ok: boolean;
  detail: string;
  status: number | null;
}

/**
 * One row per LLM provider with a "Test key" button that probes the provider's
 * models endpoint with the stored key (200 = valid). Provider list comes from
 * the backend catalog, so adding a provider needs no frontend change.
 */
export default function LlmProviderTests() {
  const [results, setResults] = useState<Record<string, { ok: boolean; detail: string }>>({});

  const { data: providers = [] } = useQuery({
    queryKey: ["llm-providers"],
    queryFn: () => api.get<LlmProvider[]>("/api/llm/providers"),
  });

  const testMut = useMutation({
    mutationFn: (id: string) => api.post<LlmTestResult>(`/api/llm/test?provider=${id}`),
    onSuccess: (r) => setResults((s) => ({ ...s, [r.provider]: { ok: r.ok, detail: r.detail } })),
    onError: (e, id) =>
      setResults((s) => ({
        ...s,
        [id]: { ok: false, detail: apiErrorText(e, "Test failed") },
      })),
  });

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
        <Bot className="h-4 w-4 text-slate-400" /> Provider key check
      </h3>
      <p className="mt-1 text-xs text-slate-400">
        Validate a stored key against the provider — it calls the provider&apos;s models endpoint; a
        200 means the key authenticates. Save the key above first.
      </p>

      <div className="mt-3 divide-y divide-slate-800/60">
        {providers.map((p) => {
          const res = results[p.id];
          const pending = testMut.isPending && testMut.variables === p.id;
          return (
            <div key={p.id} className="flex items-center gap-3 py-3">
              <span className="text-sm text-slate-200">{p.label}</span>
              {p.configured ? (
                <span className="rounded bg-emerald-600/20 px-1.5 py-0.5 text-[10px] text-emerald-400">
                  key set
                </span>
              ) : (
                <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
                  no key
                </span>
              )}
              {res && (
                <span
                  className={`flex items-center gap-1 text-xs ${
                    res.ok ? "text-emerald-400" : "text-red-400"
                  }`}
                >
                  {res.ok ? (
                    <CheckCircle2 className="h-3.5 w-3.5" />
                  ) : (
                    <XCircle className="h-3.5 w-3.5" />
                  )}
                  {res.detail}
                </span>
              )}
              <button
                type="button"
                onClick={() => testMut.mutate(p.id)}
                disabled={pending}
                className="ml-auto flex items-center gap-1.5 rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-slate-100 hover:bg-slate-600 disabled:opacity-50"
              >
                {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                {pending ? "Testing…" : "Test key"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
