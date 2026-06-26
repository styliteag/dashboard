/**
 * Configure (create / edit / delete) a Phase-2 ping monitor for one child SA.
 * The source defaults to the agent's suggestion (a box-owned IP inside the local
 * selector) — a wrong source fails the ping immediately, so we nudge a valid one.
 */
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Activity, Trash2 } from "lucide-react";
import Dialog from "./Dialog";
import { api, ApiError } from "../lib/api";
import type {
  IPsecChild,
  IPsecPingMonitor,
  PingMonitorCreate,
  PingMonitorUpdate,
  PingTestResult,
} from "../lib/types";

interface Props {
  instanceId: number;
  tunnelId: string;
  tunnelDescription: string;
  child: IPsecChild;
  existing: IPsecPingMonitor | null;
  onClose: () => void;
}

export default function PingMonitorDialog({
  instanceId,
  tunnelId,
  tunnelDescription,
  child,
  existing,
  onClose,
}: Props) {
  const queryClient = useQueryClient();
  const [source, setSource] = useState(existing?.source ?? child.suggested_source ?? "");
  const [destination, setDestination] = useState(existing?.destination ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [pingCount, setPingCount] = useState(existing?.ping_count ?? 3);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<PingTestResult | null>(null);

  const base = `/api/instances/${instanceId}/ipsec/ping-monitors`;

  // A new source/dest/count invalidates a prior test result.
  const resetTest = () => setTestResult(null);

  const testMut = useMutation({
    mutationFn: () =>
      api.post<PingTestResult>(`${base}/test`, {
        source,
        destination,
        ping_count: pingCount,
      }),
    onSuccess: (r) => {
      setTestResult(r);
      setError(null);
    },
    onError: (e) => {
      setTestResult(null);
      setError(e instanceof ApiError ? e.message : "Test failed");
    },
  });
  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["ipsec-ping-monitors", instanceId] });
    queryClient.invalidateQueries({ queryKey: ["ipsec", instanceId] });
    queryClient.invalidateQueries({ queryKey: ["vpn-overview"] });
  };

  const saveMut = useMutation({
    mutationFn: () => {
      if (existing) {
        const body: PingMonitorUpdate = {
          source,
          destination,
          enabled,
          ping_count: pingCount,
        };
        return api.patch<IPsecPingMonitor>(`${base}/${existing.id}`, body);
      }
      const body: PingMonitorCreate = {
        tunnel_id: tunnelId,
        child_name: child.name,
        local_ts: child.local_ts,
        remote_ts: child.remote_ts,
        description: tunnelDescription,
        source,
        destination,
        enabled,
        ping_count: pingCount,
      };
      return api.post<IPsecPingMonitor>(base, body);
    },
    onSuccess: () => {
      invalidate();
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : "Save failed"),
  });

  const deleteMut = useMutation({
    mutationFn: () => api.del(`${base}/${existing!.id}`),
    onSuccess: () => {
      invalidate();
      onClose();
    },
    onError: (e) => setError(e instanceof ApiError ? e.message : "Delete failed"),
  });

  const selector =
    child.local_ts || child.remote_ts
      ? `${child.local_ts || "?"} → ${child.remote_ts || "?"}`
      : child.name;

  return (
    <Dialog title="Phase 2 ping check" onClose={onClose}>
      <p className="text-xs text-slate-400">
        {tunnelDescription || tunnelId} · <span className="font-mono">{selector}</span>
      </p>

      <div className="mt-4 space-y-3">
        <label className="block">
          <span className="text-xs text-slate-400">Source IP (local, inside selector)</span>
          <input
            value={source}
            onChange={(e) => {
              setSource(e.target.value);
              resetTest();
            }}
            placeholder={child.suggested_source || "auto / default route"}
            className="mt-1 w-full rounded border border-slate-700 bg-slate-800 px-2 py-1 font-mono text-sm focus:border-emerald-600 focus:outline-none"
          />
          {child.suggested_source && source !== child.suggested_source && (
            <button
              type="button"
              onClick={() => setSource(child.suggested_source)}
              className="mt-1 text-xs text-emerald-400 hover:underline"
            >
              Use suggested: {child.suggested_source}
            </button>
          )}
        </label>

        <label className="block">
          <span className="text-xs text-slate-400">Destination IP (remote, behind tunnel)</span>
          <input
            value={destination}
            onChange={(e) => {
              setDestination(e.target.value);
              resetTest();
            }}
            placeholder="e.g. 10.2.2.1"
            className="mt-1 w-full rounded border border-slate-700 bg-slate-800 px-2 py-1 font-mono text-sm focus:border-emerald-600 focus:outline-none"
          />
        </label>

        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4"
            />
            Enabled
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            Ping count
            <input
              type="number"
              min={1}
              max={10}
              value={pingCount}
              onChange={(e) => {
                setPingCount(Number(e.target.value));
                resetTest();
              }}
              className="w-16 rounded border border-slate-700 bg-slate-800 px-2 py-1 text-sm"
            />
          </label>
        </div>

        {/* Dry-run the ping via the agent before saving. */}
        <div>
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending || !destination.trim()}
            className="inline-flex items-center gap-1 rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50"
          >
            <Activity className={`h-4 w-4 ${testMut.isPending ? "animate-pulse" : ""}`} />
            {testMut.isPending ? "Testing…" : "Test now"}
          </button>
          {testResult && (
            <div
              className={`mt-2 rounded-lg px-3 py-2 text-sm ${
                testResult.ping_state === "ok"
                  ? "bg-emerald-900/40 text-emerald-300"
                  : testResult.ping_state === "fail"
                    ? "bg-red-900/40 text-red-300"
                    : "bg-amber-900/40 text-amber-300"
              }`}
            >
              {testResult.message || testResult.ping_state}
            </div>
          )}
        </div>
      </div>

      {error && <p className="mt-3 text-sm text-red-400">{error}</p>}

      <div className="mt-5 flex items-center justify-between">
        {existing ? (
          <button
            onClick={() => deleteMut.mutate()}
            disabled={deleteMut.isPending}
            className="inline-flex items-center gap-1 rounded px-2 py-1 text-sm text-red-400 hover:bg-slate-800 disabled:opacity-50"
          >
            <Trash2 className="h-4 w-4" /> Remove
          </button>
        ) : (
          <span />
        )}
        <div className="flex gap-2">
          <button onClick={onClose} className="rounded px-3 py-1.5 text-sm text-slate-400 hover:bg-slate-800">
            Cancel
          </button>
          <button
            onClick={() => saveMut.mutate()}
            disabled={saveMut.isPending || !destination.trim()}
            className="rounded bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
          >
            Save
          </button>
        </div>
      </div>
    </Dialog>
  );
}
