/**
 * IPsec tunnel table with connect/disconnect buttons (US-4.1 .. US-4.5).
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link2, Unlink, RotateCw, Shield } from "lucide-react";
import { api, ApiError } from "../lib/api";
import type { IPsecServiceStatus, TunnelActionResponse, ActionResult } from "../lib/types";

interface Props {
  instanceId: number;
}

export default function IPsecSection({ instanceId }: Props) {
  const queryClient = useQueryClient();
  const qk = ["ipsec", instanceId];

  const { data, isLoading, isError } = useQuery({
    queryKey: qk,
    queryFn: () => api.get<IPsecServiceStatus>(`/api/instances/${instanceId}/ipsec`),
    refetchInterval: 30_000,
  });

  const [actionMsg, setActionMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const clearMsg = () => setTimeout(() => setActionMsg(null), 5000);

  const connectMut = useMutation({
    mutationFn: (tunnelId: string) =>
      api.post<TunnelActionResponse>(`/api/instances/${instanceId}/ipsec/connect/${tunnelId}`),
    onSuccess: (r) => {
      setActionMsg({ ok: r.success, text: r.success ? "Connected" : r.message });
      queryClient.invalidateQueries({ queryKey: qk });
      clearMsg();
    },
    onError: (e) => {
      setActionMsg({ ok: false, text: e instanceof ApiError ? e.message : "Error" });
      clearMsg();
    },
  });

  const disconnectMut = useMutation({
    mutationFn: (tunnelId: string) =>
      api.post<TunnelActionResponse>(`/api/instances/${instanceId}/ipsec/disconnect/${tunnelId}`),
    onSuccess: (r) => {
      setActionMsg({ ok: r.success, text: r.success ? "Disconnected" : r.message });
      queryClient.invalidateQueries({ queryKey: qk });
      clearMsg();
    },
    onError: (e) => {
      setActionMsg({ ok: false, text: e instanceof ApiError ? e.message : "Error" });
      clearMsg();
    },
  });

  const [confirmRestart, setConfirmRestart] = useState(false);
  const [restartInput, setRestartInput] = useState("");
  const restartMut = useMutation({
    mutationFn: () => api.post<ActionResult>(`/api/instances/${instanceId}/ipsec/restart`),
    onSuccess: () => {
      setActionMsg({ ok: true, text: "IPsec Service restarted" });
      setConfirmRestart(false);
      setRestartInput("");
      queryClient.invalidateQueries({ queryKey: qk });
      clearMsg();
    },
    onError: (e) => {
      setActionMsg({ ok: false, text: e instanceof ApiError ? e.message : "Error" });
      clearMsg();
    },
  });

  const busy = connectMut.isPending || disconnectMut.isPending || restartMut.isPending;

  return (
    <section className="mt-8">
      <div className="flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
          <Shield className="h-4 w-4" /> IPsec Tunnels
          {data && (
            <span className={`ml-2 text-xs ${data.running ? "text-emerald-400" : "text-red-400"}`}>
              Service {data.running ? "running" : "stopped"}
            </span>
          )}
        </h2>
        <button
          onClick={() => setConfirmRestart(true)}
          className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
        >
          <RotateCw className="h-3 w-3" /> Restart Service
        </button>
      </div>

      {/* Restart confirmation */}
      {confirmRestart && (
        <div className="mt-2 rounded-lg border border-amber-800/50 bg-amber-900/20 p-3">
          <p className="text-sm text-amber-300">
            Warning: all tunnels will be briefly interrupted. Type RESTART to confirm:
          </p>
          <div className="mt-2 flex gap-2">
            <input
              value={restartInput}
              onChange={(e) => setRestartInput(e.target.value)}
              className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-sm"
              placeholder="RESTART"
            />
            <button
              onClick={() => restartMut.mutate()}
              disabled={restartInput !== "RESTART" || restartMut.isPending}
              className="rounded bg-amber-600 px-3 py-1 text-sm font-medium text-white disabled:opacity-50"
            >
              Confirm
            </button>
            <button
              onClick={() => { setConfirmRestart(false); setRestartInput(""); }}
              className="text-sm text-slate-400"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Action feedback */}
      {actionMsg && (
        <div className={`mt-2 rounded-lg px-3 py-2 text-sm ${
          actionMsg.ok ? "bg-emerald-900/40 text-emerald-300" : "bg-red-900/40 text-red-300"
        }`}>
          {actionMsg.text}
        </div>
      )}

      {isLoading && <p className="mt-3 text-sm text-slate-500">Loading tunnels…</p>}
      {isError && <p className="mt-3 text-sm text-red-400">IPsec status not available.</p>}

      {data && data.tunnels.length > 0 && (
        <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Tunnel</th>
                <th className="px-3 py-2">Remote</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2 text-right">IN</th>
                <th className="px-3 py-2 text-right">OUT</th>
                <th className="px-3 py-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {data.tunnels.map((t) => {
                const up = t.phase1_status.toLowerCase().includes("established") ||
                           t.phase1_status.toLowerCase().includes("connected");
                return (
                  <tr key={t.id} className="border-t border-slate-800">
                    <td className="px-3 py-2">{t.description || t.id}</td>
                    <td className="px-3 py-2 font-mono text-xs">{t.remote}</td>
                    <td className="px-3 py-2">
                      <span className={up ? "text-emerald-400" : "text-red-400"}>
                        {t.phase1_status}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes_in)}</td>
                    <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes_out)}</td>
                    <td className="px-3 py-2 text-right">
                      {up ? (
                        <button
                          onClick={() => disconnectMut.mutate(t.id)}
                          disabled={busy}
                          className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-red-400 hover:bg-slate-800 disabled:opacity-50"
                        >
                          <Unlink className="h-3 w-3" /> Disconnect
                        </button>
                      ) : (
                        <button
                          onClick={() => connectMut.mutate(t.id)}
                          disabled={busy}
                          className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-emerald-400 hover:bg-slate-800 disabled:opacity-50"
                        >
                          <Link2 className="h-3 w-3" /> Connect
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {data && data.tunnels.length === 0 && (
        <p className="mt-3 text-sm text-slate-500">No IPsec tunnels configured.</p>
      )}
    </section>
  );
}

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 ** 3) return `${(b / 1024 / 1024).toFixed(1)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
