import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, ListChecks, RefreshCw } from "lucide-react";
import { api } from "../../lib/api";
import type { CheckmkConfig, CheckmkExclusionRule, CheckmkPreview } from "../../lib/types";

const CONFIG_QK = ["checkmk-config"];
const PREVIEW_QK = ["checkmk-preview"];

// Mirror of backend CATEGORIES (app/checkmk/exclusions.py) — keep in lock-step.
const CATEGORY_LABELS: Record<string, string> = {
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

// Mirror of the backend matching (app/checkmk/exclusions.py) so toggling a rule
// only needs to refetch the cheap /config — not re-poll every instance live.
function exclusionReason(
  instanceId: number,
  key: string,
  category: string,
  rules: CheckmkExclusionRule[],
): "category" | "specific" | null {
  let specific = false;
  for (const r of rules) {
    if (r.instance_id !== null && r.instance_id !== instanceId) continue;
    if (r.target === category) return "category";
    if (r.target === key) specific = true;
  }
  return specific ? "specific" : null;
}

export default function CheckmkExport() {
  const qc = useQueryClient();
  const [open, setOpen] = useState<Set<number>>(new Set());

  const { data: config } = useQuery({
    queryKey: CONFIG_QK,
    queryFn: () => api.get<CheckmkConfig>("/api/checkmk/config"),
  });
  const {
    data: preview,
    isFetching: previewLoading,
    refetch: refetchPreview,
  } = useQuery({
    queryKey: PREVIEW_QK,
    queryFn: () => api.get<CheckmkPreview>("/api/checkmk/preview"),
  });

  const rules = config?.rules ?? [];

  // Mutations only touch the lightweight /config — preview (a live poll) is
  // fetched once and refreshed manually.
  const addMut = useMutation({
    mutationFn: (body: { instance_id: number | null; target: string }) =>
      api.post("/api/checkmk/exclusions", body),
    onSuccess: () => qc.invalidateQueries({ queryKey: CONFIG_QK }),
  });
  const removeMut = useMutation({
    mutationFn: (id: number) => api.del(`/api/checkmk/exclusions/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: CONFIG_QK }),
  });

  const ruleId = (instanceId: number | null, target: string): number | undefined =>
    rules.find((r) => r.instance_id === instanceId && r.target === target)?.id;

  const toggleCategory = (cat: string, excluded: boolean) => {
    if (excluded) {
      const id = ruleId(null, cat);
      if (id != null) removeMut.mutate(id);
    } else {
      addMut.mutate({ instance_id: null, target: cat });
    }
  };

  const toggleSpecific = (instanceId: number, key: string, excluded: boolean) => {
    if (excluded) {
      const id = ruleId(instanceId, key);
      if (id != null) removeMut.mutate(id);
    } else {
      addMut.mutate({ instance_id: instanceId, target: key });
    }
  };

  const toggleOpen = (id: number) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
        <ListChecks className="h-4 w-4 text-slate-400" /> Exported checks
      </h3>
      <p className="mt-1 text-xs text-slate-400">
        Everything is exported by default. Turn off a whole category globally, or exclude a single
        service on one instance below. Exclusions affect <strong>only</strong> the Checkmk export —
        the dashboard keeps showing all checks.
      </p>

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
              checked={!c.excluded}
              onChange={() => toggleCategory(c.key, c.excluded)}
              className="h-4 w-4 cursor-pointer accent-emerald-600"
            />
          </label>
        ))}
      </div>

      {/* Per-instance live preview */}
      <div className="mt-5 flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Current export per instance
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
            const reasons = inst.checks.map((c) =>
              exclusionReason(inst.instance_id, c.key, c.category, rules),
            );
            const excludedCount = reasons.filter((r) => r !== null).length;
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
                    <span className="text-xs text-slate-500">{inst.device_type}</span>
                  </span>
                  <span className="text-xs text-slate-500">
                    {inst.checks.length} checks
                    {excludedCount > 0 && ` · ${excludedCount} excluded`}
                  </span>
                </button>

                {isOpen && (
                  <ul className="divide-y divide-slate-800/60">
                    {inst.checks.map((c, i) => {
                      const reason = reasons[i];
                      const excluded = reason !== null;
                      const viaCategory = reason === "category";
                      const badge = STATE_BADGE[c.state] ?? STATE_BADGE[3];
                      return (
                        <li
                          key={c.key}
                          className={`flex items-center gap-3 px-3 py-1.5 text-xs ${
                            excluded ? "opacity-50" : ""
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={!excluded}
                            disabled={viaCategory}
                            onChange={() => toggleSpecific(inst.instance_id, c.key, excluded)}
                            title={
                              viaCategory
                                ? "Excluded via its category toggle above"
                                : "Toggle export of this service"
                            }
                            className="h-3.5 w-3.5 cursor-pointer accent-emerald-600 disabled:cursor-not-allowed"
                          />
                          <span className={`rounded px-1.5 py-0.5 ${badge.cls}`}>
                            {badge.label}
                          </span>
                          <span className="font-mono text-slate-300">{c.key}</span>
                          <span className="truncate text-slate-500">{c.summary}</span>
                          {viaCategory && (
                            <span className="ml-auto whitespace-nowrap text-slate-600">
                              via category
                            </span>
                          )}
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
