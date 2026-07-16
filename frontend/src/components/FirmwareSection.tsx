/**
 * Firmware status card with check/update actions (US-5.1 .. US-5.3).
 */
import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Download, RefreshCw, Package, AlertTriangle, Lock } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import { useAuth, canWrite } from "../lib/use-auth";
import type { FirmwareStatus, ActionResult, FirmwareUpgradeStatus, Instance } from "../lib/types";
import { EntityCommentBadge } from "./CommentBadge";

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

  // Update/upgrade confirmation (one dialog, two severities)
  const [confirmKind, setConfirmKind] = useState<"update" | "upgrade" | null>(null);
  const [confirmName, setConfirmName] = useState("");
  const [upgrading, setUpgrading] = useState(false);
  // Keeps the upgrade log panel visible after tracking ends — it used to
  // unmount together with `upgrading`, yanking the output the moment the
  // update finished (user feedback 2026-07-16).
  const [showUpgradeLog, setShowUpgradeLog] = useState(false);
  const upgradeStartedRef = useRef(0);

  // Shared start handler: the trigger routes answer HTTP 200 with
  // success=false for agent-side refusals ("insufficient disk space", "no
  // series upgrade offered") AND for a reply timeout. Refusals must render
  // red — appending them to a green "started" line hid them entirely. A
  // timeout is special: the box may well have started (seen live on pfplus
  // under full pkg load) — start tracking and let the status poll tell the
  // truth, without the confusing "— command timed out" suffix.
  const handleStartResult = (kind: "Update" | "Series upgrade", data: ActionResult) => {
    setConfirmKind(null);
    setConfirmName("");
    if (!data.success) {
      if ((data.message || "").toLowerCase().includes("timed out")) {
        setMsg({
          ok: true,
          text: `${kind} trigger sent — waiting for the box to report progress…`,
        });
      } else {
        setMsg({ ok: false, text: data.message || `${kind} did not start` });
        clearMsg();
        return;
      }
    } else {
      // Surface the agent's start message (e.g. "boot environment
      // orbit-pre-X created") instead of swallowing it.
      const note =
        data.message && data.message !== "update started in background"
          ? ` — ${data.message}`
          : "";
      setMsg({ ok: true, text: `${kind} started. Tracking progress…${note}` });
    }
    upgradeStartedRef.current = Date.now();
    setShowUpgradeLog(true);
    setUpgrading(true);
  };

  const updateMut = useMutation({
    mutationFn: () => api.post<ActionResult>(`/api/instances/${instanceId}/firmware/update`),
    onSuccess: (data) => handleStartResult("Update", data),
    onError: (e) => {
      setMsg({ ok: false, text: apiErrorText(e, "Error") });
      clearMsg();
    },
  });

  // Series/major upgrade (e.g. OPNsense 26.1 → 26.7). The target is resolved
  // on the box itself — this only pulls the trigger.
  const upgradeMut = useMutation({
    mutationFn: () => api.post<ActionResult>(`/api/instances/${instanceId}/firmware/upgrade`),
    onSuccess: (data) => handleStartResult("Series upgrade", data),
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

  // Auto-stop polling on "done". Before refetching, force a fresh agent
  // snapshot: the agent's firmware verdict is cached ~12h, so without the
  // refresh the card keeps advertising the pre-update "N available"
  // (opn1 incident 2026-07-15). Agents predating 3.0.4 never leave
  // "unknown" on firewalls — stop tracking after 15 min instead of forever.
  useEffect(() => {
    if (!upgrading || !upgradeStatus) return;
    if (upgradeStatus.status === "done") {
      const t = setTimeout(async () => {
        setUpgrading(false);
        if (agentMode) {
          try {
            await api.post(`/api/instances/${instanceId}/agent/refresh`);
          } catch {
            // best effort — the agent self-heals its verdict on the next push
          }
        }
        queryClient.invalidateQueries({ queryKey: ["firmware", instanceId] });
        setMsg({ ok: true, text: "Update finished." });
      }, 2000);
      return () => clearTimeout(t);
    }
    if (
      upgradeStatus.status === "unknown" &&
      Date.now() - upgradeStartedRef.current > 15 * 60_000
    ) {
      setUpgrading(false);
      setMsg({
        ok: false,
        text: "No progress reported for 15 minutes — the update may still be running on the box. Check the firmware status manually.",
      });
    }
  }, [upgrading, upgradeStatus, agentMode, instanceId, queryClient]);

  return (
    <section className="mt-8">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {/* group: reveals the comment pencil on header hover (CommentBadge) */}
        <h2 className="group flex items-center gap-2 text-sm font-semibold text-slate-400">
          <Package className="h-4 w-4" /> Firmware
          <EntityCommentBadge
            instanceId={instanceId}
            kind="firmware"
            entityKey=""
            scope="instance"
          />
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
                    {(fw.security_updates ?? 0) > 0 && ` (${fw.security_updates} security)`}
                  </span>
                ) : fw.check_failed ? (
                  <span
                    className="flex items-center gap-1 text-amber-400"
                    title="The box could not check for updates (repo unreachable or pkg broken) — status unknown"
                  >
                    <AlertTriangle className="h-3.5 w-3.5" />
                    Check failed
                  </span>
                ) : fw.updates_available > 0 ? (
                  // Linux: routine (non-security) package updates pending — never amber.
                  <span className="text-slate-300">
                    {fw.updates_available} pending (none security-relevant)
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
                onClick={() => setConfirmKind("update")}
                className="flex items-center gap-1 rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-500"
              >
                <Download className="h-3.5 w-3.5" /> Start update
              </button>
            )}
            {!!fw.upgrade_major_version && agentMode && !upgrading && !firmwareLocked && (
              <button
                onClick={() => setConfirmKind("upgrade")}
                className="flex items-center gap-1 rounded-lg bg-red-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-600"
              >
                <Download className="h-3.5 w-3.5" /> Upgrade to {fw.upgrade_major_version}
              </button>
            )}
          </div>
          {fw.upgrade_available && firmwareLocked && (
            <p className="mt-2 flex items-center gap-1 text-xs text-red-400">
              <Lock className="h-3 w-3" /> Update available but locked
              {canWr ? " — uncheck the lock above to update." : "."}
            </p>
          )}

          {/* Update / series-upgrade confirmation dialog */}
          {confirmKind && (
            <div className="mt-3 rounded-lg border border-red-800/50 bg-red-900/20 p-3">
              {confirmKind === "update" ? (
                <p className="text-sm text-red-300">
                  Firmware update starts the updater and reboots the box when the update requires
                  it. Type the instance name to confirm:
                </p>
              ) : (
                <p className="text-sm text-red-300">
                  Major upgrade to <span className="font-mono">{fw.upgrade_major_version}</span>:
                  downloads the new release (~1 GB), reboots the box and continues installing
                  after boot. A ZFS boot environment is created first (on ZFS installs). Read the
                  vendor release notes before proceeding. Type the instance name to confirm:
                </p>
              )}
              {confirmKind === "update" && fw.packages.length > 0 && (
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
                  onClick={() => (confirmKind === "update" ? updateMut : upgradeMut).mutate()}
                  disabled={
                    confirmName !== instanceName || updateMut.isPending || upgradeMut.isPending
                  }
                  className="rounded bg-red-600 px-3 py-1 text-sm font-medium text-white disabled:opacity-50"
                >
                  {confirmKind === "update"
                    ? "Start update"
                    : `Upgrade to ${fw.upgrade_major_version}`}
                </button>
                <button
                  onClick={() => {
                    setConfirmKind(null);
                    setConfirmName("");
                  }}
                  className="text-sm text-slate-400"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Live upgrade log — stays visible after "done" until dismissed */}
          {(upgrading || showUpgradeLog) && upgradeStatus && (
            <div className="mt-3 rounded-lg border border-slate-700 bg-slate-950 p-3">
              <div className="flex items-center justify-between">
                <p className="text-xs text-slate-400">
                  Status:{" "}
                  <span className={upgrading ? "text-amber-400" : "text-emerald-400"}>
                    {upgradeStatus.status}
                  </span>
                </p>
                {!upgrading && (
                  <button
                    onClick={() => setShowUpgradeLog(false)}
                    className="text-xs text-slate-500 hover:text-slate-300"
                  >
                    Dismiss
                  </button>
                )}
              </div>
              {upgrading && upgradeStatus.status === "unknown" && (
                <p className="mt-1 text-xs text-slate-500">
                  The box reports no live progress — the updater runs detached or the box is
                  rebooting. Tracking continues automatically.
                </p>
              )}
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
