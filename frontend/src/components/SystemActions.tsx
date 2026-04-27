/**
 * Config backup download + reboot button for instance detail page.
 */
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Download, Power } from "lucide-react";
import { api, ApiError } from "../lib/api";

interface Props {
  instanceId: number;
  instanceName: string;
}

export default function SystemActions({ instanceId, instanceName }: Props) {
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [confirmReboot, setConfirmReboot] = useState(false);
  const [rebootInput, setRebootInput] = useState("");

  const clearMsg = () => setTimeout(() => setMsg(null), 5000);

  const rebootMut = useMutation({
    mutationFn: () => api.post<{ success: boolean; message: string }>(`/api/instances/${instanceId}/reboot`),
    onSuccess: () => {
      setMsg({ ok: true, text: "Reboot triggered." });
      setConfirmReboot(false);
      setRebootInput("");
      clearMsg();
    },
    onError: (e) => {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Error" });
      clearMsg();
    },
  });

  const handleBackup = () => {
    // Direct download via browser
    window.open(`/api/instances/${instanceId}/config-backup`, "_blank");
  };

  return (
    <section className="mt-8">
      <h2 className="text-sm font-semibold text-slate-400">System</h2>

      {msg && (
        <div className={`mt-2 rounded-lg px-3 py-2 text-sm ${
          msg.ok ? "bg-emerald-900/40 text-emerald-300" : "bg-red-900/40 text-red-300"
        }`}>
          {msg.text}
        </div>
      )}

      <div className="mt-3 flex gap-3">
        <button
          onClick={handleBackup}
          className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
        >
          <Download className="h-3.5 w-3.5" /> Config Backup
        </button>
        <button
          onClick={() => setConfirmReboot(true)}
          className="flex items-center gap-1.5 rounded-lg border border-red-800/50 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/20"
        >
          <Power className="h-3.5 w-3.5" /> Reboot
        </button>
      </div>

      {confirmReboot && (
        <div className="mt-3 rounded-lg border border-red-800/50 bg-red-900/20 p-3">
          <p className="text-sm text-red-300">
            Reboot will restart the firewall. Type the instance name to confirm:
          </p>
          <div className="mt-2 flex gap-2">
            <input
              value={rebootInput}
              onChange={(e) => setRebootInput(e.target.value)}
              className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-sm"
              placeholder={instanceName}
            />
            <button
              onClick={() => rebootMut.mutate()}
              disabled={rebootInput !== instanceName || rebootMut.isPending}
              className="rounded bg-red-600 px-3 py-1 text-sm font-medium text-white disabled:opacity-50"
            >
              Reboot
            </button>
            <button
              onClick={() => { setConfirmReboot(false); setRebootInput(""); }}
              className="text-sm text-slate-400"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
