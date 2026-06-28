import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Bell, ListChecks } from "lucide-react";
import { api } from "../../lib/api";
import type { NotificationRoutingMatrix, NotificationTestResult } from "../../lib/types";

const ROUTING_QK = ["notification-routing"];

// Display labels for the alert categories. "availability" is the instance up/down
// signal; the rest mirror the Checkmk check categories. Unknown keys fall back to
// the raw token so a new backend category still renders (just unlabelled).
const CATEGORY_LABELS: Record<string, string> = {
  availability: "Instance up / down",
  memory: "Memory",
  cpu: "CPU",
  load: "Load average",
  swap: "Swap",
  disk: "Disks",
  gateway: "Gateways",
  pf_states: "pf state table",
  ntp: "NTP sync",
  "ipsec.service": "IPsec service",
  "ipsec.tunnel": "IPsec tunnels",
  "ipsec.tunnel_ping": "IPsec ping monitors",
  service: "Vital services",
  cert: "Certificates",
  iface_errors: "Interface errors",
  firmware: "Firmware",
};

const STATUS_CLS: Record<string, string> = {
  sent: "text-emerald-400",
  skipped: "text-slate-500",
  failed: "text-red-400",
};

export default function ChannelAlertSelection({ channel }: { channel: string }) {
  const qc = useQueryClient();
  const [testResult, setTestResult] = useState<NotificationTestResult | null>(null);

  const { data } = useQuery({
    queryKey: ROUTING_QK,
    queryFn: () => api.get<NotificationRoutingMatrix>("/api/notifications/routing"),
  });

  const subscribed = new Set(
    (data?.routes ?? []).filter((r) => r.channel === channel).map((r) => r.category),
  );
  const configured = data?.channels.find((c) => c.key === channel)?.configured ?? false;

  const toggleMut = useMutation({
    mutationFn: ({ category, on }: { category: string; on: boolean }) =>
      on
        ? api.post("/api/notifications/routes", { channel, category })
        : api.del(
            `/api/notifications/routes?channel=${channel}&category=${encodeURIComponent(category)}`,
          ),
    // Refetch the shared matrix so every channel tab stays in sync.
    onSuccess: () => qc.invalidateQueries({ queryKey: ROUTING_QK }),
  });

  const testMut = useMutation({
    mutationFn: () =>
      api.post<NotificationTestResult[]>(`/api/notifications/test?channel=${channel}`),
    onSuccess: (rows) => setTestResult(rows[0] ?? null),
  });

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <ListChecks className="h-4 w-4 text-slate-400" /> Which alerts go to this channel
        </h3>
        <button
          type="button"
          onClick={() => testMut.mutate()}
          disabled={testMut.isPending}
          className="flex items-center gap-1.5 rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-slate-100 hover:bg-slate-600 disabled:opacity-50"
        >
          <Bell className="h-3.5 w-3.5" /> {testMut.isPending ? "Sending…" : "Send test"}
        </button>
      </div>
      <p className="mt-1 text-xs text-slate-400">
        Pick the alert categories this channel receives. A category stays silent here until you
        enable it — only “Instance up / down” is on by default.
      </p>

      {!configured && (
        <p className="mt-3 flex items-center gap-2 rounded-lg border border-amber-600/30 bg-amber-600/10 px-3 py-2 text-xs text-amber-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> This channel isn’t configured yet —
          subscribed alerts won’t be delivered until you fill in its settings above.
        </p>
      )}

      {testResult && (
        <p className="mt-3 text-xs">
          <span className="text-slate-400">Test: </span>
          <span className={STATUS_CLS[testResult.status] ?? "text-slate-400"}>
            {testResult.status}
          </span>
          {testResult.detail && <span className="ml-2 text-slate-600">{testResult.detail}</span>}
        </p>
      )}

      <div className="mt-4 grid gap-x-6 gap-y-2 sm:grid-cols-2">
        {(data?.categories ?? []).map((cat) => {
          const on = subscribed.has(cat);
          return (
            <label
              key={cat}
              className="flex cursor-pointer items-center gap-2 text-sm text-slate-300"
            >
              <input
                type="checkbox"
                checked={on}
                disabled={toggleMut.isPending}
                onChange={() => toggleMut.mutate({ category: cat, on: !on })}
                className="h-4 w-4 rounded border-slate-600 bg-slate-800 text-emerald-600 focus:ring-emerald-600"
              />
              {CATEGORY_LABELS[cat] ?? cat}
            </label>
          );
        })}
      </div>
    </div>
  );
}
