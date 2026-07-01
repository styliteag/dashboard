/**
 * Last agent collection timing — whole cycle + per section — from the most recent
 * push. Live snapshot only (not stored as history): it answers "which collector is
 * slow right now" without digging into checks. Empty until a timing-aware agent
 * (>= 2.3.3) has pushed at least once.
 */
import { Timer } from "lucide-react";
import type { SystemStatus } from "../lib/types";

const WARN_MS = 10_000;

function fmt(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`;
}

export default function AgentRuntimeSection({ status }: { status?: SystemStatus }) {
  const total = status?.collect_ms ?? null;
  const sections = Object.entries(status?.section_ms ?? {}).sort((a, b) => b[1] - a[1]);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
        <Timer className="h-4 w-4 text-slate-400" /> Collection runtime
      </h3>
      <p className="mt-1 text-xs text-slate-400">
        How long the agent&apos;s last metrics push took to gather, per section. Latest snapshot
        only — not history. The whole-cycle total is graphed under the Overview tab.
      </p>

      {total == null ? (
        <p className="mt-4 text-sm text-slate-600">No collection timing reported yet.</p>
      ) : (
        <>
          <div className="mt-4 flex items-baseline gap-2">
            <span
              className={`text-2xl font-semibold ${
                total >= WARN_MS ? "text-amber-400" : "text-slate-100"
              }`}
            >
              {(total / 1000).toFixed(1)}s
            </span>
            <span className="text-xs text-slate-500">
              total{total >= WARN_MS ? " · over the 10s warning" : ""}
            </span>
          </div>

          <div className="mt-4 space-y-1.5">
            {sections.map(([name, ms]) => (
              <div key={name} className="flex items-center gap-3 text-xs">
                <span className="w-28 shrink-0 truncate font-mono text-slate-300" title={name}>
                  {name}
                </span>
                <div className="h-1.5 flex-1 rounded bg-slate-800">
                  <div
                    className={`h-1.5 rounded ${ms >= WARN_MS ? "bg-amber-500" : "bg-emerald-500/70"}`}
                    style={{
                      width: `${total ? Math.max(2, Math.min(100, (ms / total) * 100)) : 0}%`,
                    }}
                  />
                </div>
                <span className="w-14 shrink-0 text-right font-mono text-slate-400">{fmt(ms)}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
