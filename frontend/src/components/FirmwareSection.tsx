/**
 * Firmware status card with check/update actions (US-5.1 .. US-5.3).
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Download, RefreshCw, Package, AlertTriangle, Lock } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import { useAuth, canWrite } from "../lib/use-auth";
import type { FirmwareStatus, ActionResult, FirmwareUpgradeStatus, Instance } from "../lib/types";

interface Props {
  instanceId: number;
  instanceName: string;
  agentMode?: boolean;
  firmwareLocked?: boolean;
}

export default function FirmwareSection({
  instanceId,
  instanceName,
  agentMode,
  firmwareLocked,
}: Props) {
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canWr = canWrite(user);
  const qk = ["firmware", instanceId];

  const {
    data: fw,
    isLoading,
    isError,
  } = useQuery({
    queryKey: qk,
    queryFn: () => api.get<FirmwareStatus>(`/api/instances/${instanceId}/firmware`),
    // Agent mode: refetch every 60s so the first push appears quickly.
    // Polling mode: 5min is fine since the OPNsense API is slow.
    refetchInterval: agentMode ? 60_000 : 300_000,
    retry: 1,
  });

  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const clearMsg = () => setTimeout(() => setMsg(null), 5000);

  const checkMut = useMutation({
    mutationFn: () => api.post<ActionResult>(`/api/instances/${instanceId}/firmware/check`),
    onSuccess: () => {
      setMsg({ ok: true, text: "Update check triggered. Please reload in 30s." });
      clearMsg();
      setTimeout(() => queryClient.invalidateQueries({ queryKey: qk }), 30_000);
    },
    onError: (e) => {
      setMsg({ ok: false, text: apiErrorText(e, "Error") });
      clearMsg();
    },
  });

  const lockMut = useMutation({
    mutationFn: (locked: boolean) =>
      api.patch<Instance>(`/api/instances/${instanceId}`, { firmware_locked: locked }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["instance", String(instanceId)] });
      queryClient.invalidateQueries({ queryKey: ["instances"] });
    },
    onError: (e) => {
      setMsg({ ok: false, text: apiErrorText(e, "Failed to update firmware lock") });
      clearMsg();
    },
  });

  // Update confirmation
  const [confirmUpdate, setConfirmUpdate] = useState(false);
  const [confirmName, setConfirmName] = useState("");
  const [upgrading, setUpgrading] = useState(false);

  const updateMut = useMutation({
    mutationFn: () => api.post<ActionResult>(`/api/instances/${instanceId}/firmware/update`),
    onSuccess: () => {
      setMsg({ ok: true, text: "Update started. Tracking progress…" });
      setConfirmUpdate(false);
      setConfirmName("");
      setUpgrading(true);
    },
    onError: (e) => {
      setMsg({ ok: false, text: apiErrorText(e, "Error") });
      clearMsg();
    },
  });

  // Poll upgrade status while upgrading
  const { data: upgradeStatus } = useQuery({
    queryKey: ["upgrade-status", instanceId],
    queryFn: () =>
      api.get<FirmwareUpgradeStatus>(`/api/instances/${instanceId}/firmware/upgradestatus`),
    enabled: upgrading,
    refetchInterval: 5_000,
  });

  // Auto-stop polling when done
  if (upgrading && upgradeStatus && upgradeStatus.status === "done") {
    setTimeout(() => {
      setUpgrading(false);
      queryClient.invalidateQueries({ queryKey: qk });
    }, 2000);
  }

  return (
    <section className="mt-8">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
          <Package className="h-4 w-4" /> Firmware
        </h2>
        {canWr ? (
          <label className="flex items-center gap-1.5 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={!!firmwareLocked}
              onChange={(e) => lockMut.mutate(e.target.checked)}
              disabled={lockMut.isPending}
              className="rounded border-slate-600"
            />
            <Lock className="h-3 w-3" />
            Lock firmware updates for this instance
          </label>
        ) : (
          firmwareLocked && (
            <span
              className="flex items-center gap-1 rounded bg-red-900/40 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-red-300"
              title="Firmware updates are locked for this instance"
            >
              <Lock className="h-3 w-3" /> Locked
            </span>
          )
        )}
      </div>

      {msg && (
        <div
          className={`mt-2 rounded-lg px-3 py-2 text-sm ${
            msg.ok ? "bg-emerald-900/40 text-emerald-300" : "bg-red-900/40 text-red-300"
          }`}
        >
          {msg.text}
        </div>
      )}

      {isLoading && <p className="mt-3 text-sm text-slate-500">Loading firmware status…</p>}
      {isError && <p className="mt-3 text-sm text-red-400">Firmware status not available.</p>}

      {fw && (
        <div className="mt-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="grid gap-3 sm:grid-cols-4">
            <div>
              <p className="text-xs text-slate-500">Installed</p>
              <p className="font-mono text-sm">{fw.product_version || "—"}</p>
            </div>
            {fw.branch && (
              <div>
                <p className="text-xs text-slate-500">Branch / Train</p>
                <p className="font-mono text-sm text-slate-300">{fw.branch}</p>
                {fw.known_branches && fw.known_branches.length > 1 && (
                  <p className="mt-0.5 text-[10px] text-slate-500">
                    other:{" "}
                    {fw.known_branches
                      .filter((b) => b !== fw.branch)
                      .slice(0, 3)
                      .join(", ")}
                  </p>
                )}
              </div>
            )}
            <div>
              <p className="text-xs text-slate-500">Latest</p>
              <p className="font-mono text-sm">{fw.product_latest || fw.product_version || "—"}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Updates</p>
              <p className="text-sm">
                {fw.upgrade_available ? (
                  <span className="flex items-center gap-1 text-amber-400">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    {fw.updates_available} available
                  </span>
                ) : fw.check_failed ? (
                  <span
                    className="flex items-center gap-1 text-amber-400"
                    title="The box could not check for updates (repo unreachable or pkg broken) — status unknown"
                  >
                    <AlertTriangle className="h-3.5 w-3.5" />
                    Check failed
                  </span>
                ) : (
                  <span className="text-emerald-400">Up to date</span>
                )}
              </p>
            </div>
          </div>

          {fw.status_msg && <p className="mt-3 text-sm text-slate-300">{fw.status_msg}</p>}
          {fw.last_check && (
            <p className="mt-1 text-xs text-slate-500">Last check: {fw.last_check}</p>
          )}
          {fw.needs_reboot && <p className="mt-2 text-sm text-amber-400">Reboot required.</p>}

          {/* Package/set list */}
          {fw.packages.length > 0 && (
            <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full text-xs">
                <thead className="bg-slate-900 text-left text-slate-500">
                  <tr>
                    <th className="px-3 py-1.5">Package</th>
                    <th className="px-3 py-1.5">Current</th>
                    <th className="px-3 py-1.5">New</th>
                  </tr>
                </thead>
                <tbody>
                  {fw.packages.map((p, i) => (
                    <tr key={i} className="border-t border-slate-800">
                      <td className="px-3 py-1.5 font-mono">{String(p.name)}</td>
                      <td className="px-3 py-1.5 text-slate-400">{String(p.current || "—")}</td>
                      <td className="px-3 py-1.5 text-emerald-400">{String(p.new || "—")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="mt-4 flex gap-2">
            <button
              onClick={() => checkMut.mutate()}
              disabled={checkMut.isPending}
              className="flex items-center gap-1 rounded-lg px-3 py-1.5 text-xs text-slate-400 hover:bg-slate-800 disabled:opacity-50"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              {checkMut.isPending ? "…" : "Check"}
            </button>

            {fw.upgrade_available && !upgrading && !firmwareLocked && (
              <button
                onClick={() => setConfirmUpdate(true)}
                className="flex items-center gap-1 rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-500"
              >
                <Download className="h-3.5 w-3.5" /> Start update
              </button>
            )}
          </div>
          {fw.upgrade_available && firmwareLocked && (
            <p className="mt-2 flex items-center gap-1 text-xs text-red-400">
              <Lock className="h-3 w-3" /> Update available but locked
              {canWr ? " — uncheck the lock above to update." : "."}
            </p>
          )}

          {/* Update confirmation dialog */}
          {confirmUpdate && (
            <div className="mt-3 rounded-lg border border-red-800/50 bg-red-900/20 p-3">
              <p className="text-sm text-red-300">
                Firmware update starts the updater and reboots the box when the update requires it.
                Type the instance name to confirm:
              </p>
              {fw.packages.length > 0 && (
                <ul className="mt-2 max-h-32 overflow-y-auto text-xs text-slate-400">
                  {fw.packages.map((p, i) => (
                    <li key={i}>
                      {String(p.name)}: {String(p.current ?? "—")} → {String(p.new ?? "—")}
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-2 flex gap-2">
                <input
                  value={confirmName}
                  onChange={(e) => setConfirmName(e.target.value)}
                  className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-sm"
                  placeholder={instanceName}
                />
                <button
                  onClick={() => updateMut.mutate()}
                  disabled={confirmName !== instanceName || updateMut.isPending}
                  className="rounded bg-red-600 px-3 py-1 text-sm font-medium text-white disabled:opacity-50"
                >
                  Start update
                </button>
                <button
                  onClick={() => {
                    setConfirmUpdate(false);
                    setConfirmName("");
                  }}
                  className="text-sm text-slate-400"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Live upgrade log */}
          {upgrading && upgradeStatus && (
            <div className="mt-3 rounded-lg border border-slate-700 bg-slate-950 p-3">
              <p className="text-xs text-slate-400">
                Status: <span className="text-amber-400">{upgradeStatus.status}</span>
              </p>
              {upgradeStatus.log.length > 0 && (
                <pre className="mt-2 max-h-48 overflow-y-auto text-xs text-slate-500">
                  {upgradeStatus.log.join("\n")}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
