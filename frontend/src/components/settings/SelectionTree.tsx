import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Bell,
  ChevronDown,
  ChevronRight,
  ListChecks,
  RefreshCw,
} from "lucide-react";
import { api } from "../../lib/api";
import { resolveClient } from "../../lib/selection";
import {
  deviceTypeLabel,
  type NotificationTestResult,
  type SelectionConfig,
  type SelectionPreview,
  type SelectionRule,
} from "../../lib/types";

// Display labels for every selectable category. "availability" (instance up/down)
// is channel-only; the rest mirror the backend check categories. Keep in lock-step
// with app/selection/model.py CHECK_CATEGORIES. Unknown keys fall back to the token.
const CATEGORY_LABELS: Record<string, string> = {
  availability: "Instance up / down",
  agent: "Agent liveness",
  maintenance: "Maintenance mode",
  ping: "ICMP reachability",
  http: "HTTP reachability",
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
  connectivity: "Connectivity pings",
  service: "Vital services",
  cert: "Certificates",
  iface_errors: "Interface errors",
  firmware: "Firmware",
};

const STATE_BADGE: Record<number, { cls: string; label: string }> = {
  0: { cls: "bg-emerald-600/20 text-emerald-400", label: "OK" },
  1: { cls: "bg-amber-600/20 text-amber-400", label: "WARN" },
  2: { cls: "bg-red-600/20 text-red-400", label: "CRIT" },
  3: { cls: "bg-slate-700 text-slate-300", label: "UNKNOWN" },
};

const STATUS_CLS: Record<string, string> = {
  sent: "text-emerald-400",
  skipped: "text-slate-500",
  failed: "text-red-400",
};

const BY_NOTE: Record<string, string> = {
  instance: "forced on (this box)",
  instance_category: "via box category",
  global: "via global",
  global_category: "via category",
  default: "off",
};

export default function SelectionTree({ consumer }: { consumer: string }) {
  const qc = useQueryClient();
  const isChannel = consumer !== "checkmk";
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [testResult, setTestResult] = useState<NotificationTestResult | null>(null);

  const CONFIG_QK = ["selection-config", consumer];
  const PREVIEW_QK = ["selection-preview", consumer];

  const { data: config } = useQuery({
    queryKey: CONFIG_QK,
    queryFn: () => api.get<SelectionConfig>(`/api/selection/${consumer}/config`),
  });
  const {
    data: preview,
    isFetching: previewLoading,
    refetch: refetchPreview,
  } = useQuery({
    queryKey: PREVIEW_QK,
    queryFn: () => api.get<SelectionPreview>(`/api/selection/${consumer}/preview`),
  });

  const rules = config?.rules ?? [];

  const addMut = useMutation({
    mutationFn: (body: {
      instance_id: number | null;
      selector: string;
      mode: "include" | "exclude";
    }) => api.post(`/api/selection/${consumer}/rules`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: CONFIG_QK }),
  });
  const removeMut = useMutation({
    mutationFn: ({ selector, instance_id }: { selector: string; instance_id: number | null }) => {
      const q = `selector=${encodeURIComponent(selector)}`;
      return api.del(
        `/api/selection/${consumer}/rules?${q}${instance_id === null ? "" : `&instance_id=${instance_id}`}`,
      );
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: CONFIG_QK }),
  });
  const testMut = useMutation({
    mutationFn: () => api.post<NotificationTestResult[]>(`/api/selection/${consumer}/test`),
    onSuccess: (rows) => setTestResult(rows[0] ?? null),
  });

  const pending = addMut.isPending || removeMut.isPending;

  const instanceRuleFor = (instanceId: number, key: string): SelectionRule | undefined =>
    rules.find((r) => r.instance_id === instanceId && r.selector === key);

  // Global category checkbox: presence of a global include rule. Check = add it;
  // uncheck = remove it (the category falls back to base-default off).
  const toggleCategory = (cat: string, included: boolean) => {
    if (included) removeMut.mutate({ selector: cat, instance_id: null });
    else addMut.mutate({ instance_id: null, selector: cat, mode: "include" });
  };

  // Per-service checkbox at instance scope. If an explicit instance rule exists,
  // clicking clears it (back to inherit). Otherwise it writes an instance override
  // opposite to the effective value: on→exclude (mute), off→include (add).
  const toggleService = (instanceId: number, key: string, on: boolean) => {
    const existing = instanceRuleFor(instanceId, key);
    if (existing) removeMut.mutate({ selector: key, instance_id: instanceId });
    else
      addMut.mutate({ instance_id: instanceId, selector: key, mode: on ? "exclude" : "include" });
  };

  const toggleOpen = (id: number) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  const configured = config?.configured ?? null;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <ListChecks className="h-4 w-4 text-slate-400" />{" "}
          {isChannel ? "Which alerts go to this channel" : "Exported checks"}
        </h3>
        {isChannel && (
          <button
            type="button"
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending}
            className="flex items-center gap-1.5 rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-slate-100 hover:bg-slate-600 disabled:opacity-50"
          >
            <Bell className="h-3.5 w-3.5" /> {testMut.isPending ? "Sending…" : "Send test"}
          </button>
        )}
      </div>
      <p className="mt-1 text-xs text-slate-400">
        Nothing is selected by default. Turn on a whole category globally, or add/mute a single
        service on one instance below.{" "}
        {isChannel
          ? "A box-level choice wins over the global one."
          : "Selection affects only the Checkmk export — the dashboard keeps showing all checks."}
      </p>

      {isChannel && configured === false && (
        <p className="mt-3 flex items-center gap-2 rounded-lg border border-amber-600/30 bg-amber-600/10 px-3 py-2 text-xs text-amber-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> This channel isn’t configured yet —
          selected alerts won’t be delivered until you fill in its settings above.
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

      {/* Global category toggles */}
      <div className="mt-4 grid gap-2 sm:grid-cols-2">
        {config?.categories.map((c) => (
          <label
            key={c.key}
            className="flex cursor-pointer items-center justify-between rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2"
          >
            <span className="text-sm text-slate-300">{CATEGORY_LABELS[c.key] ?? c.key}</span>
            <input
              type="checkbox"
              checked={c.included}
              disabled={pending}
              onChange={() => toggleCategory(c.key, c.included)}
              className="h-4 w-4 cursor-pointer accent-emerald-600 disabled:cursor-not-allowed"
            />
          </label>
        ))}
      </div>

      {/* Per-instance live preview tree */}
      <div className="mt-5 flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          {isChannel ? "Per instance" : "Current export per instance"}
        </h4>
        <button
          type="button"
          onClick={() => refetchPreview()}
          className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
        >
          <RefreshCw className={`h-3 w-3 ${previewLoading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {previewLoading && !preview ? (
        <p className="mt-2 text-xs text-slate-500">Polling instances…</p>
      ) : (
        <div className="mt-2 space-y-2">
          {preview?.instances.map((inst) => {
            const isOpen = open.has(inst.instance_id);
            const states = inst.checks.map((c) => resolveClient(c.key, inst.instance_id, rules));
            const onCount = states.filter((s) => s.on).length;
            return (
              <div
                key={inst.instance_id}
                className="overflow-hidden rounded-lg border border-slate-800"
              >
                <button
                  type="button"
                  onClick={() => toggleOpen(inst.instance_id)}
                  className="flex w-full items-center justify-between bg-slate-900/70 px-3 py-2 text-left hover:bg-slate-900"
                >
                  <span className="flex items-center gap-2 text-sm text-slate-200">
                    {isOpen ? (
                      <ChevronDown className="h-3 w-3 text-slate-500" />
                    ) : (
                      <ChevronRight className="h-3 w-3 text-slate-500" />
                    )}
                    {inst.name}
                    <span className="text-xs text-slate-500">
                      {deviceTypeLabel(inst.device_type)}
                    </span>
                  </span>
                  <span className="text-xs text-slate-500">
                    {onCount}/{inst.checks.length} selected
                  </span>
                </button>

                {isOpen && (
                  <ul className="divide-y divide-slate-800/60">
                    {inst.checks.map((c, i) => {
                      const st = states[i];
                      const explicit = instanceRuleFor(inst.instance_id, c.key) !== undefined;
                      const badge = STATE_BADGE[c.state] ?? STATE_BADGE[3];
                      return (
                        <li
                          key={c.key}
                          className={`flex items-center gap-3 px-3 py-1.5 text-xs ${
                            st.on ? "" : "opacity-50"
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={st.on}
                            disabled={pending}
                            onChange={() => toggleService(inst.instance_id, c.key, st.on)}
                            title="Toggle this service for this instance"
                            className="h-3.5 w-3.5 cursor-pointer accent-emerald-600 disabled:cursor-not-allowed"
                          />
                          <span className={`rounded px-1.5 py-0.5 ${badge.cls}`}>
                            {badge.label}
                          </span>
                          <span className="font-mono text-slate-300">{c.key}</span>
                          <span className="truncate text-slate-500">{c.summary}</span>
                          <span className="ml-auto flex items-center gap-2 whitespace-nowrap">
                            <span className="text-slate-600">{BY_NOTE[st.by] ?? st.by}</span>
                            {explicit && (
                              <button
                                type="button"
                                onClick={() =>
                                  removeMut.mutate({
                                    selector: c.key,
                                    instance_id: inst.instance_id,
                                  })
                                }
                                disabled={pending}
                                title="Clear this box-level override and inherit"
                                className="text-slate-500 hover:text-slate-300 disabled:opacity-50"
                              >
                                ↺
                              </button>
                            )}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            );
          })}
          {preview && preview.instances.length === 0 && (
            <p className="text-xs text-slate-500">No instances.</p>
          )}
        </div>
      )}
    </div>
  );
}
