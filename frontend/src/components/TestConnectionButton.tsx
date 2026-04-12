import { useState } from "react";
import { Zap } from "lucide-react";
import { api } from "../lib/api";
import type { TestConnectionResult } from "../lib/types";

interface Props {
  instanceId: number;
}

export default function TestConnectionButton({ instanceId }: Props) {
  const [state, setState] = useState<"idle" | "loading" | "ok" | "error">("idle");
  const [result, setResult] = useState<TestConnectionResult | null>(null);

  const handleClick = async () => {
    setState("loading");
    try {
      const res = await api.post<TestConnectionResult>(
        `/api/instances/${instanceId}/test`,
      );
      setResult(res);
      setState(res.ok ? "ok" : "error");
    } catch {
      setState("error");
      setResult(null);
    }
    // Auto-reset after 5s
    setTimeout(() => {
      setState("idle");
      setResult(null);
    }, 5000);
  };

  const label = {
    idle: "Test",
    loading: "…",
    ok: result ? `OK ${result.latency_ms}ms` : "OK",
    error: result?.error ? "Fehler" : "Fehler",
  }[state];

  const color = {
    idle: "text-slate-400 hover:bg-slate-800 hover:text-slate-200",
    loading: "text-slate-500",
    ok: "text-emerald-400",
    error: "text-red-400",
  }[state];

  return (
    <button
      onClick={handleClick}
      disabled={state === "loading"}
      className={`flex items-center gap-1 rounded-md px-2 py-1 text-xs ${color}`}
      title={result?.error ?? "Verbindung testen"}
    >
      <Zap className="h-3 w-3" />
      {label}
    </button>
  );
}
