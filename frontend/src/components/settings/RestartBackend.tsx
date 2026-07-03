import { useRef, useState } from "react";
import { Power } from "lucide-react";
import { api } from "../../lib/api";

type Phase = "idle" | "confirm" | "restarting" | "failed";

const HEALTH_POLL_MS = 2000;
const HEALTH_TIMEOUT_MS = 60000;

async function waitForBackend(): Promise<boolean> {
  const deadline = Date.now() + HEALTH_TIMEOUT_MS;
  // First probe after a beat — the old process needs a moment to actually die.
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, HEALTH_POLL_MS));
    try {
      await api.get("/api/health");
      return true;
    } catch {
      // still down — keep polling
    }
  }
  return false;
}

/** Admin action card: restart the backend process (applies "needs restart"
 * settings). Two-step confirm, then polls /api/health and reloads the page
 * once the new process answers. */
export default function RestartBackend() {
  const [phase, setPhase] = useState<Phase>("idle");
  const confirmTimer = useRef<ReturnType<typeof setTimeout>>();

  const onClick = async () => {
    if (phase === "idle") {
      setPhase("confirm");
      clearTimeout(confirmTimer.current);
      confirmTimer.current = setTimeout(() => setPhase("idle"), 5000);
      return;
    }
    if (phase !== "confirm") return;
    clearTimeout(confirmTimer.current);
    setPhase("restarting");
    try {
      await api.post("/api/settings/restart");
    } catch {
      setPhase("failed");
      return;
    }
    if (await waitForBackend()) {
      window.location.reload();
    } else {
      setPhase("failed");
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
        <Power className="h-4 w-4 text-slate-400" /> Backend service
      </h3>
      <div className="mt-2 flex items-start justify-between gap-4">
        <p className="text-xs text-slate-400">
          Restart the backend process to apply “needs restart” settings. Takes a few seconds — the
          UI reconnects automatically, agents re-attach on their own.
        </p>
        <button
          type="button"
          onClick={onClick}
          disabled={phase === "restarting"}
          className={`shrink-0 rounded-lg px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40 ${
            phase === "confirm" ? "bg-red-600 hover:bg-red-500" : "bg-slate-700 hover:bg-slate-600"
          }`}
        >
          {phase === "confirm"
            ? "Click again to restart"
            : phase === "restarting"
              ? "Restarting…"
              : "Restart backend"}
        </button>
      </div>
      {phase === "restarting" && (
        <p className="mt-2 text-xs text-amber-400">
          Backend is restarting — this page reloads automatically once it is back.
        </p>
      )}
      {phase === "failed" && (
        <p className="mt-2 text-xs text-red-400">
          Backend did not come back within 60s. Check the container logs; the page may still
          recover on a manual reload.
        </p>
      )}
    </div>
  );
}
