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

// "global" = a route with instance_id null (every instance); a number scopes it to
// one instance. Matching is override/precedence (see app/notifications/routing.py):
// a per-instance route wins over the global one. So at instance scope a category is
// tri-state — inherit the global value, or explicitly override it on/off for that
// one box. Global scope stays a plain on/off.
type Scope = "global" | number;

// A category's resolved state at the current scope.
//   on:       effective — does this channel get the category for this scope?
//   inherit:  instance scope only — no per-instance row, so the global value applies.
//   globalOn: is the global route on (the value an instance row would override)?
type CatState = { on: boolean; inherit: boolean; globalOn: boolean };

export default function ChannelAlertSelection({ channel }: { channel: string }) {
  const qc = useQueryClient();
  const [testResult, setTestResult] = useState<NotificationTestResult | null>(null);
  const [scope, setScope] = useState<Scope>("global");

  const { data } = useQuery({
    queryKey: ROUTING_QK,
    queryFn: () => api.get<NotificationRoutingMatrix>("/api/notifications/routing"),
  });

  const channelRoutes = (data?.routes ?? []).filter((r) => r.channel === channel);
  // Global routes are pure presence (always enabled); a category is global-on when a
  // global row exists for it.
  const globalCats = new Set(
    channelRoutes.filter((r) => r.instance_id === null && r.enabled).map((r) => r.category),
  );
  // Per-instance override rows for the selected instance: category -> enabled.
  const overrides = new Map<string, boolean>(
    typeof scope === "number"
      ? channelRoutes
          .filter((r) => r.instance_id === scope)
          .map((r) => [r.category, r.enabled] as [string, boolean])
      : [],
  );
  const configured = data?.channels.find((c) => c.key === channel)?.configured ?? false;
  const instances = data?.instances ?? [];

  // Per category at the current scope. At instance scope a per-instance override (if
  // present) wins over the global value; otherwise the category inherits the global.
  const stateOf = (cat: string): CatState => {
    const globalOn = globalCats.has(cat);
    if (scope === "global") return { on: globalOn, inherit: false, globalOn };
    if (overrides.has(cat)) return { on: overrides.get(cat)!, inherit: false, globalOn };
    return { on: globalOn, inherit: true, globalOn };
  };

  const iid = scope === "global" ? null : scope;

  // Upsert a route (global on/off via add+remove; per-instance via an explicit
  // enabled flag so a global-on category can be overridden off for one box).
  const setMut = useMutation({
    mutationFn: ({ category, enabled }: { category: string; enabled: boolean }) =>
      api.post("/api/notifications/routes", { instance_id: iid, channel, category, enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ROUTING_QK }),
  });

  // Remove a route row: at global scope this turns the category off for all; at
  // instance scope it clears the override and the category falls back to inherit.
  const clearMut = useMutation({
    mutationFn: (category: string) => {
      const q = `channel=${channel}&category=${encodeURIComponent(category)}`;
      return api.del(`/api/notifications/routes?${q}${iid === null ? "" : `&instance_id=${iid}`}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ROUTING_QK }),
  });

  const pending = setMut.isPending || clearMut.isPending;

  // Toggling the checkbox. Global scope: presence add/remove. Instance scope: write
  // an explicit override opposite to the effective value (upserts on or off).
  const toggle = (cat: string, st: CatState) => {
    if (scope === "global") {
      if (st.on) clearMut.mutate(cat);
      else setMut.mutate({ category: cat, enabled: true });
      return;
    }
    setMut.mutate({ category: cat, enabled: !st.on });
  };

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
        Pick the alert categories this channel receives. Choose a scope: <em>All instances</em>{" "}
        applies to every firewall; pick one to override categories for just that box — add extra
        ones, or switch a global category off. A box-level choice wins over the global one; clear
        it (↺) to fall back to the global value.
      </p>

      {/* Scope selector — global vs one instance. */}
      <div className="mt-3 flex items-center gap-2">
        <label className="text-xs font-medium text-slate-400">Scope</label>
        <select
          value={scope === "global" ? "global" : String(scope)}
          onChange={(e) => setScope(e.target.value === "global" ? "global" : Number(e.target.value))}
          className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-sm text-slate-100"
        >
          <option value="global">All instances (global)</option>
          {instances.map((i) => (
            <option key={i.id} value={i.id}>
              {i.name} ({i.device_type})
            </option>
          ))}
        </select>
      </div>

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
          const st = stateOf(cat);
          // Tri-state at instance scope: an inheriting box shows the checkbox as
          // indeterminate (the global value applies but isn't an explicit choice).
          // `indeterminate` is a DOM property, not a JSX prop — set it via a ref.
          return (
            <div key={cat} className="flex items-center gap-2 text-sm">
              <label className="flex flex-1 cursor-pointer items-center gap-2 text-slate-300">
                <input
                  type="checkbox"
                  checked={st.on}
                  ref={(el) => {
                    if (el) el.indeterminate = st.inherit;
                  }}
                  disabled={pending}
                  onChange={() => toggle(cat, st)}
                  className="h-4 w-4 rounded border-slate-600 bg-slate-800 text-emerald-600 focus:ring-emerald-600 disabled:cursor-not-allowed"
                />
                <span className={st.inherit ? "text-slate-400" : undefined}>
                  {CATEGORY_LABELS[cat] ?? cat}
                </span>
              </label>
              {st.inherit ? (
                <span className="text-xs text-slate-600">
                  via global · {st.globalOn ? "on" : "off"}
                </span>
              ) : scope !== "global" ? (
                <button
                  type="button"
                  onClick={() => clearMut.mutate(cat)}
                  disabled={pending}
                  title="Clear the override and inherit the global value"
                  className="text-xs text-slate-500 hover:text-slate-300 disabled:opacity-50"
                >
                  ↺ {st.on ? "on" : "off"}
                </button>
              ) : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}
