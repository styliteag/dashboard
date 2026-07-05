import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDown,
  ArrowUp,
  Check,
  Copy,
  GripVertical,
  Lock,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Shield,
  Trash2,
  Unlock,
  X,
} from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import type {
  FirewallActionResult,
  FirewallRule,
  FirewallRuleDetail,
  FirewallRuleOptions,
  FirewallRuleSearchResponse,
} from "../lib/types";
import type { FormEvent, ReactNode } from "react";

interface Props {
  instanceId: number;
}

interface InterfaceOption {
  value: string;
  label: string;
  type: string;
}

interface CategoryOption {
  uuid: string;
  name: string;
}

interface RuleForm {
  enabled: boolean;
  log: boolean;
  quick: boolean;
  action: string;
  interfaceValue: string;
  direction: string;
  ipprotocol: string;
  protocol: string;
  source_not: boolean;
  source_net: string;
  source_port: string;
  destination_not: boolean;
  destination_net: string;
  destination_port: string;
  gateway: string;
  categories: string[];
  description: string;
  advanced: string;
}

const COMMON_FIELDS = new Set([
  "enabled",
  "log",
  "quick",
  "action",
  "interface",
  "direction",
  "ipprotocol",
  "protocol",
  "source_not",
  "source_net",
  "source_port",
  "destination_not",
  "destination_net",
  "destination_port",
  "gateway",
  "categories",
  "description",
]);

const DEFAULT_RULE: Record<string, unknown> = {
  enabled: "1",
  log: "0",
  quick: "1",
  action: "pass",
  interface: "lan",
  direction: "in",
  ipprotocol: "inet",
  protocol: "any",
  source_not: "0",
  source_net: "any",
  source_port: "",
  destination_not: "0",
  destination_net: "any",
  destination_port: "",
  gateway: "",
  categories: "",
  description: "",
};

function truthy(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  return ["1", "true", "yes", "on", "enabled"].includes(String(value ?? "").toLowerCase());
}

function text(value: unknown, fallback = ""): string {
  if (Array.isArray(value))
    return value
      .map((item) => text(item))
      .filter(Boolean)
      .join(", ");
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    for (const key of ["selected", "value", "label", "text", "__text"]) {
      const candidate = record[key];
      if (candidate != null && typeof candidate !== "object") return String(candidate);
    }
    for (const [key, candidate] of Object.entries(record)) {
      if (
        candidate &&
        typeof candidate === "object" &&
        truthy((candidate as { selected?: unknown }).selected)
      ) {
        const selected = candidate as Record<string, unknown>;
        return text(selected.value ?? selected.label ?? key);
      }
    }
    const truthyKeys = Object.entries(record)
      .filter(([, candidate]) => truthy(candidate))
      .map(([key]) => key);
    if (truthyKeys.length > 0) return truthyKeys.join(", ");
  }
  return String(value ?? fallback);
}

function csv(value: unknown): string[] {
  return text(value)
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
}

// Multi-value fields (interface, source_net, destination_net) arrive from get_rule
// either as a plain comma-separated string (NetworkAliasField) or as an option map
// {token: {value, selected}} (InterfaceField). Return the selected *storable
// tokens* (the keys, e.g. "lan,wan") — never the display labels ("LAN,WAN").
function selectedTokens(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(selectedTokens).filter(Boolean).join(",");
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    const isOptionMap = entries.some(
      ([, v]) => v && typeof v === "object" && "selected" in (v as object),
    );
    if (isOptionMap) {
      return entries
        .filter(([, v]) => truthy((v as { selected?: unknown }).selected))
        .map(([key]) => key)
        .join(",");
    }
    return text(value);
  }
  return String(value);
}

function ruleToForm(rule: Record<string, unknown>): RuleForm {
  const full = { ...DEFAULT_RULE, ...rule };
  const advanced: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rule)) {
    if (!COMMON_FIELDS.has(key)) advanced[key] = value;
  }
  return {
    enabled: truthy(full.enabled),
    log: truthy(full.log),
    quick: truthy(full.quick),
    action: text(full.action, "pass"),
    interfaceValue: selectedTokens(full.interface),
    direction: text(full.direction, "in"),
    ipprotocol: text(full.ipprotocol, "inet"),
    protocol: text(full.protocol, "any"),
    source_not: truthy(full.source_not),
    source_net: selectedTokens(full.source_net) || "any",
    source_port: text(full.source_port),
    destination_not: truthy(full.destination_not),
    destination_net: selectedTokens(full.destination_net) || "any",
    destination_port: text(full.destination_port),
    gateway: text(full.gateway),
    categories: csv(full.categories),
    description: text(full.description),
    advanced: JSON.stringify(advanced, null, 2),
  };
}

function formToRule(form: RuleForm): Record<string, unknown> {
  const advanced = JSON.parse(form.advanced || "{}") as Record<string, unknown>;
  return {
    ...advanced,
    enabled: form.enabled ? "1" : "0",
    log: form.log ? "1" : "0",
    quick: form.quick ? "1" : "0",
    action: form.action,
    interface: form.interfaceValue,
    direction: form.direction,
    ipprotocol: form.ipprotocol,
    protocol: form.protocol,
    source_not: form.source_not ? "1" : "0",
    source_net: form.source_net || "any",
    source_port: form.source_port,
    destination_not: form.destination_not ? "1" : "0",
    destination_net: form.destination_net || "any",
    destination_port: form.destination_port,
    gateway: form.gateway,
    categories: form.categories.join(","),
    description: form.description,
  };
}

function interfaceOptions(options?: FirewallRuleOptions): InterfaceOption[] {
  const root = options?.interfaces ?? {};
  const out: InterfaceOption[] = [];
  for (const section of Object.values(root)) {
    if (!section || typeof section !== "object" || !("items" in section)) continue;
    const items = (section as { items?: unknown }).items;
    if (!Array.isArray(items)) continue;
    for (const item of items) {
      if (!item || typeof item !== "object") continue;
      const value = text((item as { value?: unknown }).value);
      const label = text((item as { label?: unknown }).label, value);
      const type = text((item as { type?: unknown }).type);
      // The "All rules" (__any) tab is rendered separately and pinned first —
      // skip OPNsense's own copy so it doesn't appear twice.
      if (!value || type === "any") continue;
      // Shorten OPNsense's verbose enc0 label.
      out.push({ value, label: label === "IPsec encapsulation" ? "IPsec" : label, type });
    }
  }
  return out;
}

function categoryOptions(options?: FirewallRuleOptions): CategoryOption[] {
  const rows = (options?.categories as { rows?: unknown } | undefined)?.rows;
  if (!Array.isArray(rows)) return [];
  return rows
    .map((row) => {
      if (!row || typeof row !== "object") return null;
      return {
        uuid: text((row as { uuid?: unknown }).uuid),
        name: text((row as { name?: unknown }).name),
      };
    })
    .filter((row): row is CategoryOption => Boolean(row?.uuid && row.name));
}

function groupedItems(root: Record<string, unknown> | undefined) {
  const out: string[] = [];
  for (const section of Object.values(root ?? {})) {
    if (!section || typeof section !== "object" || !("items" in section)) continue;
    const items = (section as { items?: unknown }).items;
    if (!items || typeof items !== "object" || Array.isArray(items)) continue;
    out.push(...Object.keys(items));
  }
  return [...new Set(out)].sort((a, b) => a.localeCompare(b));
}

function display(value: string, fallback = "any") {
  return value.trim() || fallback;
}

function rulesEndpoint(instanceId: number, iface: string, search: string) {
  const qs = new URLSearchParams();
  qs.set("interface", iface);
  qs.set("show_all", "true");
  qs.set("row_count", "500");
  if (search.trim()) qs.set("search", search.trim());
  return `/api/instances/${instanceId}/firewall/rules?${qs.toString()}`;
}

function actionOk(result?: FirewallActionResult) {
  const token = (result?.result || result?.status || "").trim().toLowerCase();
  return ["saved", "deleted", "enabled", "disabled", "ok", "done"].includes(token);
}

function resultMessage(result?: FirewallActionResult) {
  if (!result) return "";
  if (actionOk(result)) return result.result || result.status || "ok";
  return JSON.stringify(result.raw || result, null, 2);
}

export default function FirewallRulesSection({ instanceId }: Props) {
  const queryClient = useQueryClient();
  const [iface, setIface] = useState("__any");
  const [draftSearch, setDraftSearch] = useState("");
  const [search, setSearch] = useState("");
  const [pendingApply, setPendingApply] = useState(false);
  const [editing, setEditing] = useState<{ uuid: string | null; clone: boolean } | null>(null);
  const [lastResult, setLastResult] = useState<FirewallActionResult | null>(null);
  const [showReadOnly, setShowReadOnly] = useState(false);

  const optionsQuery = useQuery({
    queryKey: ["firewall-rule-options", instanceId],
    queryFn: () =>
      api.get<FirewallRuleOptions>(`/api/instances/${instanceId}/firewall/rules/options`),
    retry: 1,
  });
  const aliasesQuery = useQuery({
    queryKey: ["firewall-aliases", instanceId],
    queryFn: () => api.get<{ aliases: Array<{ name: string; address?: string | null }> }>(`/api/instances/${instanceId}/firewall/aliases`),
    retry: 1,
  });
  const aliasDetails = useMemo(() => {
    const list = aliasesQuery.data?.aliases ?? [];
    return list.map((a) => ({ name: a.name, address: a.address || null }));
  }, [aliasesQuery.data]);

  const ifaces = useMemo(() => interfaceOptions(optionsQuery.data), [optionsQuery.data]);
  const categories = useMemo(() => categoryOptions(optionsQuery.data), [optionsQuery.data]);
  const networkValues = useMemo(() => {
    const fromOptions = groupedItems(optionsQuery.data?.networks);
    const fromAliases = aliasDetails.map((a) => a.name);
    return [...new Set([...fromOptions, ...fromAliases])].sort((a, b) => a.localeCompare(b));
  }, [optionsQuery.data, aliasDetails]);
  const portValues = useMemo(() => groupedItems(optionsQuery.data?.ports), [optionsQuery.data]);

  const rulesQuery = useQuery({
    queryKey: ["firewall-rules", instanceId, iface, search],
    queryFn: () => api.get<FirewallRuleSearchResponse>(rulesEndpoint(instanceId, iface, search)),
    retry: 1,
  });

  const invalidateRules = async () => {
    await queryClient.invalidateQueries({ queryKey: ["firewall-rules", instanceId] });
  };

  const writeMutation = useMutation({
    mutationFn: async ({
      method,
      path,
      body,
    }: {
      method: "post" | "put" | "del";
      path: string;
      body?: unknown;
    }) => {
      if (method === "put") return api.put<FirewallActionResult>(path, body);
      if (method === "del") return api.del<FirewallActionResult>(path);
      return api.post<FirewallActionResult>(path, body);
    },
    onSuccess: async (result) => {
      setLastResult(result);
      if (actionOk(result)) {
        setPendingApply(true);
        setEditing(null);
        await invalidateRules();
      }
    },
  });

  const applyMutation = useMutation({
    mutationFn: () =>
      api.post<FirewallActionResult>(`/api/instances/${instanceId}/firewall/rules/apply`),
    onSuccess: async (result) => {
      setLastResult(result);
      if (actionOk(result)) {
        setPendingApply(false);
        await invalidateRules();
      }
    },
  });

  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    setSearch(draftSearch);
  };

  const rows = rulesQuery.data?.rows ?? [];
  const editableCount = rows.filter((r) => r.editable).length;
  const visibleRows = showReadOnly ? rows : rows.filter((r) => r.editable);
  const hiddenReadOnlyCount = rows.length - visibleRows.length;
  const busy = writeMutation.isPending || applyMutation.isPending;

  const mutate = (path: string, body?: unknown) =>
    writeMutation.mutate({ method: "post", path, body });
  const moveRule = (selected_uuid: string, target_uuid: string) =>
    mutate(`/api/instances/${instanceId}/firewall/rules/move`, { selected_uuid, target_uuid });

  return (
    <section className="mt-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="flex items-center gap-1.5 text-sm font-semibold text-slate-300">
            <Shield className="h-3.5 w-3.5 text-emerald-400" />
            Firewall rules
            <span className="ml-1 text-[10px] font-normal text-slate-500">— drag to reorder</span>
          </h2>
          <div className="mt-0.5 flex flex-wrap gap-2 text-[11px] text-slate-500">
            <span>{visibleRows.length} shown</span>
            <span>{editableCount} editable</span>
            <span>{rows.length - editableCount} read-only</span>
            {!showReadOnly && hiddenReadOnlyCount > 0 && <span>{hiddenReadOnlyCount} hidden</span>}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {pendingApply && (
            <button
              type="button"
              onClick={() => applyMutation.mutate()}
              disabled={busy}
              className="inline-flex h-7 items-center gap-1 rounded-md bg-amber-500 px-2.5 text-xs font-medium text-slate-950 hover:bg-amber-400 disabled:opacity-50"
            >
              <Check className="h-3.5 w-3.5" />
              Apply
            </button>
          )}
          <button
            type="button"
            onClick={() => setEditing({ uuid: null, clone: false })}
            disabled={busy}
            className="inline-flex h-7 items-center gap-1 rounded-md bg-emerald-600 px-2.5 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            Add
          </button>

          <label className="inline-flex h-7 items-center gap-1.5 rounded-md border border-slate-800 bg-slate-900 px-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={showReadOnly}
              onChange={(event) => setShowReadOnly(event.target.checked)}
              className="h-3.5 w-3.5 rounded border-slate-700 bg-slate-900 text-emerald-600"
            />
            Show read-only
          </label>

          <form onSubmit={submitSearch} className="flex items-center gap-1.5">
            <label className="flex h-7 items-center gap-1.5 rounded-md border border-slate-800 bg-slate-900 px-2 text-xs text-slate-300">
              <Search className="h-3.5 w-3.5 text-slate-500" />
              <input
                value={draftSearch}
                onChange={(event) => setDraftSearch(event.target.value)}
                placeholder="Search"
                className="w-36 bg-transparent text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none"
              />
            </label>
            <button
              type="submit"
              className="h-7 rounded-md border border-slate-700 px-2.5 text-xs text-slate-300 hover:bg-slate-800"
            >
              Apply
            </button>
          </form>

          <button
            type="button"
            onClick={() => rulesQuery.refetch()}
            className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-slate-700 text-slate-300 hover:bg-slate-800"
            title="Refresh rules"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${rulesQuery.isFetching ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Interface tabs (pfSense-style primary navigation, dark/slate theme) */}
      {ifaces.length > 0 && (
        <div className="mt-1 flex flex-wrap gap-1">
          <Tab active={iface === "__any"} onClick={() => setIface("__any")} label="All rules" />
          {ifaces.map((item) => (
            <Tab
              key={`${item.type}-${item.value}`}
              active={iface === item.value}
              onClick={() => setIface(item.value)}
              label={item.label}
            />
          ))}
        </div>
      )}

      {(lastResult || writeMutation.error || applyMutation.error) && (
        <div
          className={`mt-4 rounded-md border px-3 py-2 text-sm ${
            lastResult && actionOk(lastResult)
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
              : "border-red-500/30 bg-red-500/10 text-red-200"
          }`}
        >
          {writeMutation.error
            ? apiErrorText(writeMutation.error, "Rule action failed")
            : applyMutation.error
              ? apiErrorText(applyMutation.error, "Apply failed")
              : resultMessage(lastResult ?? undefined)}
        </div>
      )}

      {rulesQuery.isLoading && <p className="mt-6 text-sm text-slate-500">Loading rules...</p>}
      {rulesQuery.isError && (
        <p className="mt-6 text-sm text-red-400">
          {apiErrorText(rulesQuery.error, "Failed to load firewall rules")}
        </p>
      )}

      {!rulesQuery.isLoading && !rulesQuery.isError && (
        <div className="mt-3 overflow-x-auto rounded-md border border-slate-800">
          <table className="min-w-full divide-y divide-slate-800 text-left text-xs">
            <thead className="bg-slate-900 text-[10px] uppercase tracking-normal text-slate-500">
              <tr>
                <Th>Status</Th>
                <Th>Action</Th>
                <Th>Interface</Th>
                <Th>Protocol</Th>
                <Th>Source</Th>
                <Th>Destination</Th>
                <Th>Gateway</Th>
                <Th>Description</Th>
                <Th>Tools</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-900 bg-slate-950">
              {visibleRows.map((rule, index) => (
                <RuleRow
                  key={rule.uuid || `${rule.sort_order}-${rule.description}`}
                  rule={rule}
                  prev={previousMovable(visibleRows, index)}
                  next={nextMovable(visibleRows, index)}
                  busy={busy}
                  onEdit={() => setEditing({ uuid: rule.uuid, clone: false })}
                  onClone={() => setEditing({ uuid: rule.uuid, clone: true })}
                  onDelete={() => {
                    if (
                      window.confirm(`Delete firewall rule "${rule.description || rule.uuid}"?`)
                    ) {
                      writeMutation.mutate({
                        method: "del",
                        path: `/api/instances/${instanceId}/firewall/rules/${rule.uuid}`,
                      });
                    }
                  }}
                  onToggle={() =>
                    mutate(
                      `/api/instances/${instanceId}/firewall/rules/${rule.uuid}/toggle?enabled=${!rule.enabled}`,
                    )
                  }
                  onToggleLog={() =>
                    mutate(
                      `/api/instances/${instanceId}/firewall/rules/${rule.uuid}/toggle-log?log=${!rule.log}`,
                    )
                  }
                  onMoveUp={(targetUuid) => moveRule(rule.uuid, targetUuid)}
                  onMoveDown={(nextUuid) => moveRule(nextUuid, rule.uuid)}
                  onDragReorder={(sourceUuid, targetUuid) => moveRule(sourceUuid, targetUuid)}
                  aliases={aliasDetails}
                />
              ))}
              {visibleRows.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-3 py-8 text-center text-sm text-slate-500">
                    {rows.length === 0 ? "No rules." : "Only read-only rules match this view."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {editing && (
        <RuleDialog
          instanceId={instanceId}
          edit={editing}
          interfaces={ifaces}
          categories={categories}
          networks={networkValues}
          ports={portValues}
          aliases={aliasDetails}
          defaultInterface={iface.startsWith("__") ? "" : iface}
          onClose={() => setEditing(null)}
          onSave={(uuid, rule) =>
            writeMutation.mutate({
              method: uuid ? "put" : "post",
              path: uuid
                ? `/api/instances/${instanceId}/firewall/rules/${uuid}`
                : `/api/instances/${instanceId}/firewall/rules`,
              body: { rule },
            })
          }
        />
      )}
    </section>
  );
}

function previousMovable(rows: FirewallRule[], index: number) {
  const rule = rows[index];
  if (!rule.editable) return null;
  for (let i = index - 1; i >= 0; i -= 1) {
    if (rows[i].editable && rows[i].prio_group === rule.prio_group) return rows[i];
  }
  return null;
}

function nextMovable(rows: FirewallRule[], index: number) {
  const rule = rows[index];
  if (!rule.editable) return null;
  for (let i = index + 1; i < rows.length; i += 1) {
    if (rows[i].editable && rows[i].prio_group === rule.prio_group) return rows[i];
  }
  return null;
}

function RuleDialog({
  instanceId,
  edit,
  interfaces,
  categories,
  networks,
  ports,
  aliases = [],
  defaultInterface = "",
  onClose,
  onSave,
}: {
  instanceId: number;
  edit: { uuid: string | null; clone: boolean };
  interfaces: InterfaceOption[];
  categories: CategoryOption[];
  networks: string[];
  ports: string[];
  aliases?: Array<{ name: string; address?: string | null }>;
  defaultInterface?: string;
  onClose: () => void;
  onSave: (uuid: string | null, rule: Record<string, unknown>) => void;
}) {
  const detailQuery = useQuery({
    queryKey: ["firewall-rule-detail", instanceId, edit.uuid, edit.clone],
    queryFn: () =>
      api.get<FirewallRuleDetail>(
        edit.uuid
          ? `/api/instances/${instanceId}/firewall/rules/${edit.uuid}?copy=${edit.clone}`
          : `/api/instances/${instanceId}/firewall/rules/template`,
      ),
  });
  const [form, setForm] = useState<RuleForm | null>(null);
  const [jsonError, setJsonError] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    if (!detailQuery.data) return;
    const next = ruleToForm(detailQuery.data.rule);
    // Seed a new rule's interface from the active tab (unless "All rules"/floating).
    if (!edit.uuid && !next.interfaceValue && defaultInterface) {
      next.interfaceValue = defaultInterface;
    }
    setForm(next);
  }, [detailQuery.data, edit.uuid, defaultInterface]);

  const effectiveForm = form;

  const setField = <K extends keyof RuleForm>(key: K, value: RuleForm[K]) => {
    setForm((old) => ({ ...(old ?? ruleToForm(detailQuery.data?.rule ?? {})), [key]: value }));
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!effectiveForm) return;
    try {
      const rule = formToRule(effectiveForm);
      setJsonError("");
      onSave(edit.clone ? null : edit.uuid, rule);
    } catch (error) {
      setJsonError(error instanceof Error ? error.message : "Invalid advanced JSON");
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 px-4 py-10">
      <form
        onSubmit={submit}
        className="w-full max-w-5xl rounded-md border border-slate-800 bg-slate-950 shadow-xl"
      >
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <h3 className="text-sm font-semibold text-slate-200">
            {edit.uuid
              ? edit.clone
                ? "Clone Firewall Rule"
                : "Edit Firewall Rule"
              : "Add Firewall Rule"}
          </h3>
          <button type="button" onClick={onClose} className="text-slate-500 hover:text-slate-200">
            <X className="h-5 w-5" />
          </button>
        </div>

        {detailQuery.isLoading && <p className="p-5 text-sm text-slate-500">Loading rule...</p>}
        {detailQuery.isError && (
          <p className="p-5 text-sm text-red-400">
            {apiErrorText(detailQuery.error, "Failed to load rule")}
          </p>
        )}

        {effectiveForm && (
          <div className="p-5 space-y-6 text-sm">
            {/* Action */}
            <div>
              <div className="flex items-center gap-2">
                <label className="w-28 text-xs font-medium text-slate-400">Action</label>
                <Select
                  label=""
                  value={effectiveForm.action}
                  onChange={(v) => setField("action", v)}
                >
                  <option value="pass">Pass</option>
                  <option value="block">Block</option>
                  <option value="reject">Reject</option>
                </Select>
              </div>
              <p className="mt-1 ml-28 text-[10px] text-slate-500">
                Choose what to do with packets that match the criteria below.
              </p>
            </div>

            {/* Interface + Address Family + Protocol */}
            <div className="grid gap-4 md:grid-cols-3">
              <div>
                <div className="flex items-start gap-2">
                  <label className="mt-1 w-28 text-xs font-medium text-slate-400">Interface</label>
                  <div className="flex-1">
                    <MultiSelectInput
                      label=""
                      value={effectiveForm.interfaceValue}
                      options={interfaces.map((i) => i.value)}
                      labels={Object.fromEntries(interfaces.map((i) => [i.value, i.label]))}
                      exclusive={null}
                      emptyValue=""
                      emptyLabel="floating (any)"
                      placeholder="add interface…"
                      onChange={(v) => setField("interfaceValue", v)}
                    />
                  </div>
                </div>
                <p className="mt-1 ml-28 text-[10px] text-slate-500">
                  One or more interfaces; leave empty for a floating rule.
                </p>
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <label className="w-28 text-xs font-medium text-slate-400">Address Family</label>
                  <Select
                    label=""
                    value={effectiveForm.ipprotocol}
                    onChange={(v) => setField("ipprotocol", v)}
                  >
                    <option value="inet">IPv4</option>
                    <option value="inet6">IPv6</option>
                    <option value="inet46">Any</option>
                  </Select>
                </div>
                <p className="mt-1 ml-28 text-[10px] text-slate-500">Select IPv4, IPv6 or Any.</p>
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <label className="w-28 text-xs font-medium text-slate-400">Protocol</label>
                  <Select
                    label=""
                    value={effectiveForm.protocol}
                    onChange={(v) => setField("protocol", v)}
                  >
                    <option value="any">any</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="TCP/UDP">TCP/UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="IGMP">IGMP</option>
                    <option value="ESP">ESP</option>
                    <option value="AH">AH</option>
                    <option value="GRE">GRE</option>
                  </Select>
                </div>
                <p className="mt-1 ml-28 text-[10px] text-slate-500">
                  Choose the IP protocol to match.
                </p>
              </div>
            </div>

            {/* Disabled */}
            <div>
              <div className="flex items-center gap-2">
                <label className="w-28 text-xs font-medium text-slate-400">Disabled</label>
                <Checkbox
                  label="Disable this rule"
                  checked={!effectiveForm.enabled}
                  onChange={(v) => setField("enabled", !v)}
                />
              </div>
              <p className="mt-1 ml-28 text-[10px] text-slate-500">
                Set this option to disable the rule without removing it.
              </p>
            </div>

            {/* Source Section */}
            <div className="rounded border border-slate-800 bg-slate-900/50 p-4">
              <div className="mb-3 text-xs font-semibold tracking-wide text-slate-300">Source</div>
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <Checkbox
                    label="Invert match"
                    checked={effectiveForm.source_not}
                    onChange={(v) => setField("source_not", v)}
                  />
                  <span className="text-[10px] text-slate-500">Invert source match</span>
                </div>

                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <MultiSelectInput
                    label="Source"
                    value={effectiveForm.source_net}
                    options={networks}
                    aliases={aliases}
                    placeholder="add network or alias…"
                    onChange={(v) => setField("source_net", v)}
                  />
                  <ComboInput
                    label="Source Port Range"
                    value={effectiveForm.source_port}
                    options={ports}
                    onChange={(v) => setField("source_port", v)}
                  />
                </div>
                <p className="text-[10px] text-slate-500">
                  The Source Port Range is typically random. In most cases leave as &quot;any&quot;.
                </p>
              </div>
            </div>

            {/* Destination Section */}
            <div className="rounded border border-slate-800 bg-slate-900/50 p-4">
              <div className="mb-3 text-xs font-semibold tracking-wide text-slate-300">
                Destination
              </div>
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <Checkbox
                    label="Invert match"
                    checked={effectiveForm.destination_not}
                    onChange={(v) => setField("destination_not", v)}
                  />
                  <span className="text-[10px] text-slate-500">Invert destination match</span>
                </div>

                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <MultiSelectInput
                    label="Destination"
                    value={effectiveForm.destination_net}
                    options={networks}
                    aliases={aliases}
                    placeholder="add network or alias…"
                    onChange={(v) => setField("destination_net", v)}
                  />
                  <ComboInput
                    label="Destination Port Range"
                    value={effectiveForm.destination_port}
                    options={ports}
                    onChange={(v) => setField("destination_port", v)}
                  />
                </div>
                <p className="text-[10px] text-slate-500">
                  Specify the destination address or network and optional port range.
                </p>
              </div>
            </div>

            {/* Gateway + Description */}
            <div className="grid gap-4 md:grid-cols-2">
              <TextInput
                label="Gateway"
                value={effectiveForm.gateway}
                onChange={(v) => setField("gateway", v)}
              />
              <TextInput
                label="Description"
                value={effectiveForm.description}
                onChange={(v) => setField("description", v)}
              />
            </div>

            {/* Extra Options */}
            <div className="rounded border border-slate-800 bg-slate-900/50 p-4">
              <div className="mb-3 text-xs font-semibold tracking-wide text-slate-300">
                Extra Options
              </div>
              <div className="flex flex-wrap gap-x-6 gap-y-2">
                <Checkbox
                  label="Log packets that are handled by this rule"
                  checked={effectiveForm.log}
                  onChange={(v) => setField("log", v)}
                />
                <Checkbox
                  label="Quick (first match)"
                  checked={effectiveForm.quick}
                  onChange={(v) => setField("quick", v)}
                />
              </div>
              <p className="mt-2 text-[10px] text-slate-500">
                Log: enable logging for this rule. Quick: apply this rule immediately (first match
                wins).
              </p>
            </div>

            {/* Categories */}
            {categories.length > 0 && (
              <div>
                <div className="mb-2 text-xs font-medium text-slate-400">Categories</div>
                <div className="flex flex-wrap gap-2">
                  {categories.map((cat) => (
                    <button
                      key={cat.uuid}
                      type="button"
                      onClick={() => {
                        const selected = new Set(effectiveForm.categories);
                        if (selected.has(cat.uuid)) selected.delete(cat.uuid);
                        else selected.add(cat.uuid);
                        setField("categories", [...selected]);
                      }}
                      className={`rounded-md border px-2 py-1 text-xs ${
                        effectiveForm.categories.includes(cat.uuid)
                          ? "border-emerald-500 bg-emerald-500/10 text-emerald-200"
                          : "border-slate-800 text-slate-400 hover:bg-slate-900"
                      }`}
                    >
                      {cat.name}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Advanced */}
            <div className="border-t border-slate-800 pt-4">
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-emerald-300 hover:bg-slate-800"
              >
                ⚙ Display Advanced
              </button>

              {showAdvanced && (
                <div className="mt-3">
                  <label className="block text-xs font-medium text-slate-400">
                    Advanced fields (JSON)
                  </label>
                  <textarea
                    value={effectiveForm.advanced}
                    onChange={(event) => setField("advanced", event.target.value)}
                    rows={7}
                    spellCheck={false}
                    className="mt-1 w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 outline-none focus:border-emerald-600"
                  />
                  {jsonError && <p className="mt-1 text-xs text-red-400">{jsonError}</p>}
                  <p className="mt-1 text-[10px] text-slate-500">
                    Advanced OPNsense-specific fields (e.g. source OS, TCP flags, etc.) live here.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        <div className="flex justify-end gap-2 border-t border-slate-800 px-5 py-4">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!effectiveForm}
            className="rounded-md bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            Save
          </button>
        </div>
      </form>
    </div>
  );
}

function Th({ children }: { children: ReactNode }) {
  return <th className="whitespace-nowrap px-2 py-1.5 font-medium">{children}</th>;
}

function RuleRow({
  rule,
  prev,
  next,
  busy,
  aliases = [],
  onEdit,
  onClone,
  onDelete,
  onToggle,
  onToggleLog,
  onMoveUp,
  onMoveDown,
  onDragReorder,
}: {
  rule: FirewallRule;
  prev: FirewallRule | null;
  next: FirewallRule | null;
  busy: boolean;
  aliases?: Array<{ name: string; address?: string | null }>;
  onEdit: () => void;
  onClone: () => void;
  onDelete: () => void;
  onToggle: () => void;
  onToggleLog: () => void;
  onMoveUp: (targetUuid: string) => void;
  onMoveDown: (nextUuid: string) => void;
  onDragReorder?: (sourceUuid: string, targetUuid: string) => void;
}) {
  const resolveAlias = (val: string) => {
    if (!val || val === "any") return val;
    const match = aliases.find((a) => a.name === val);
    if (match && match.address) {
      return `${val} (${match.address})`;
    }
    return val;
  };
  const destination = `${resolveAlias(display(rule.destination))}${rule.destination_port ? `:${rule.destination_port}` : ""}`;
  const source = `${resolveAlias(display(rule.source))}${rule.source_port ? `:${rule.source_port}` : ""}`;
  const handleDragStart = (e: React.DragEvent<HTMLTableRowElement>) => {
    if (!rule.editable) return;
    e.dataTransfer.setData("text/plain", rule.uuid);
    e.dataTransfer.effectAllowed = "move";
  };

  const handleDragOver = (e: React.DragEvent<HTMLTableRowElement>) => {
    if (rule.editable) e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent<HTMLTableRowElement>) => {
    e.preventDefault();
    const sourceUuid = e.dataTransfer.getData("text/plain");
    if (sourceUuid && sourceUuid !== rule.uuid && rule.editable && onDragReorder) {
      onDragReorder(sourceUuid, rule.uuid);
    }
  };

  return (
    <tr
      className={`${rule.enabled ? "" : "opacity-55"} hover:bg-slate-900/60 ${rule.editable ? "cursor-move" : ""}`}
      draggable={rule.editable}
      onDragStart={handleDragStart}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      <td className="whitespace-nowrap px-2 py-1 align-middle">
        <div className="flex items-center gap-1.5">
          {rule.editable && (
            <span
              title="Drag to reorder"
              className="cursor-grab text-slate-500 hover:text-slate-300 active:cursor-grabbing"
            >
              <GripVertical className="h-3 w-3" />
            </span>
          )}
          {rule.editable ? (
            <Unlock className="h-3 w-3 text-emerald-400" />
          ) : (
            <Lock className="h-3 w-3 text-slate-500" />
          )}
          <button
            type="button"
            disabled={!rule.editable || busy}
            onClick={onToggle}
            className={`rounded px-1.5 py-0.5 text-[11px] leading-none ${
              rule.enabled ? "bg-emerald-500/10 text-emerald-300" : "bg-slate-800 text-slate-400"
            } ${rule.editable ? "hover:ring-1 hover:ring-slate-600" : ""}`}
          >
            {rule.enabled ? "enabled" : "disabled"}
          </button>
          <button
            type="button"
            disabled={!rule.editable || busy}
            onClick={onToggleLog}
            className={`rounded px-1.5 py-0.5 text-[11px] leading-none ${
              rule.log ? "bg-sky-500/10 text-sky-300" : "bg-slate-800 text-slate-500"
            } ${rule.editable ? "hover:ring-1 hover:ring-slate-600" : ""}`}
          >
            log
          </button>
        </div>
      </td>
      <td className="whitespace-nowrap px-2 py-1 align-middle">
        {(() => {
          const a = (rule.action || "-").toLowerCase();
          const cls =
            a === "pass"
              ? "bg-emerald-500/10 text-emerald-300"
              : a === "block" || a === "reject"
                ? "bg-red-500/10 text-red-300"
                : "bg-slate-700 text-slate-300";
          return (
            <span className={`inline-block rounded px-1.5 py-px text-[10px] font-medium ${cls}`}>
              {display(rule.action, "-")}
            </span>
          );
        })()}
      </td>
      <td className="whitespace-nowrap px-2 py-1 align-middle">
        <span className="inline-block rounded bg-slate-800 px-1.5 py-px text-[10px] text-slate-300">
          {display(rule.interfaces, "floating")}
        </span>
      </td>
      <td className="whitespace-nowrap px-2 py-1 align-middle text-slate-300">
        {[rule.ip_protocol, rule.protocol].filter(Boolean).join(" / ") || "any"}
      </td>
      <td className="max-w-xs px-2 py-1 align-middle text-slate-300">
        <span className="break-words">{source}</span>
      </td>
      <td className="max-w-xs px-2 py-1 align-middle text-slate-300">
        <span className="break-words">{destination}</span>
      </td>
      <td className="whitespace-nowrap px-2 py-1 align-middle text-slate-400">
        {display(rule.gateway, "-")}
      </td>
      <td className="min-w-60 px-2 py-1 align-middle">
        <div className="text-slate-200">{rule.description || "-"}</div>
        {!rule.editable && <div className="text-[10px] text-slate-500">read-only</div>}
      </td>
      <td className="whitespace-nowrap px-2 py-1 align-middle">
        <div className="flex items-center gap-0.5">
          <IconButton
            label="Move up"
            disabled={!prev || busy}
            onClick={() => prev && onMoveUp(prev.uuid)}
          >
            <ArrowUp className="h-3 w-3" />
          </IconButton>
          <IconButton
            label="Move down"
            disabled={!next || busy}
            onClick={() => next && onMoveDown(next.uuid)}
          >
            <ArrowDown className="h-3 w-3" />
          </IconButton>
          <IconButton label="Edit" disabled={!rule.editable || busy} onClick={onEdit}>
            <Pencil className="h-3 w-3" />
          </IconButton>
          <IconButton label="Clone" disabled={!rule.editable || busy} onClick={onClone}>
            <Copy className="h-3 w-3" />
          </IconButton>
          <IconButton label="Delete" disabled={!rule.editable || busy} onClick={onDelete} danger>
            <Trash2 className="h-3 w-3" />
          </IconButton>
        </div>
      </td>
    </tr>
  );
}

function IconButton({
  label,
  disabled,
  danger = false,
  onClick,
  children,
}: {
  label: string;
  disabled: boolean;
  danger?: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      title={label}
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex h-6 w-6 items-center justify-center rounded border border-slate-800 ${
        danger ? "text-red-300 hover:bg-red-500/10" : "text-slate-400 hover:bg-slate-800"
      } disabled:cursor-not-allowed disabled:opacity-35`}
    >
      {children}
    </button>
  );
}

function TextInput({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  if (!label) {
    return (
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-600"
      />
    );
  }
  return (
    <label className="block text-xs font-medium text-slate-500">
      {label}
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-1 w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-600"
      />
    </label>
  );
}

function ComboInput({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  if (!label) {
    const listId = `fw-combo-${Math.random().toString(36).slice(2)}`;
    return (
      <>
        <input
          value={value}
          list={listId}
          onChange={(event) => onChange(event.target.value)}
          className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-600"
        />
        <datalist id={listId}>
          {options.map((option) => (
            <option key={option} value={option} />
          ))}
        </datalist>
      </>
    );
  }
  const listId = `fw-${label.toLowerCase().replace(/\W+/g, "-")}`;
  return (
    <label className="block text-xs font-medium text-slate-500">
      {label}
      <input
        value={value}
        list={listId}
        onChange={(event) => onChange(event.target.value)}
        className="mt-1 w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-600"
      />
      <datalist id={listId}>
        {options.map((option) => (
          <option key={option} value={option} />
        ))}
      </datalist>
    </label>
  );
}

// Multi-value picker for OPNsense Source/Destination (the model's source_net /
// destination_net and interface are all Multiple=Y). The value stays a
// comma-separated string so it round-trips unchanged through ruleToForm/
// formToRule. `exclusive` is a token that can't coexist with others ("any" for
// Source/Dest); `emptyValue` is what an empty selection serialises to ("any"
// there, "" = floating for interface). `labels` maps a stored token to its
// display text (interface value → friendly name).
function MultiSelectInput({
  label,
  value,
  options,
  aliases = [],
  labels = {},
  exclusive = "any",
  emptyValue = "any",
  emptyLabel = "any",
  placeholder = "add…",
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  aliases?: Array<{ name: string; address?: string | null }>;
  labels?: Record<string, string>;
  exclusive?: string | null;
  emptyValue?: string;
  emptyLabel?: string;
  placeholder?: string;
  onChange: (value: string) => void;
}) {
  const [draft, setDraft] = useState("");
  const tokens = value
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  const isEmpty =
    tokens.length === 0 || (!!exclusive && tokens.length === 1 && tokens[0] === exclusive);

  const commit = (raw: string) => {
    const v = raw.trim();
    setDraft("");
    if (!v) return;
    if (exclusive && v === exclusive) return onChange(exclusive);
    const base = tokens.filter((t) => t !== exclusive && t !== v);
    onChange([...base, v].join(","));
  };
  const remove = (t: string) => {
    const next = tokens.filter((x) => x !== t);
    onChange(next.length ? next.join(",") : emptyValue);
  };

  const listId = `fw-multi-${label.toLowerCase().replace(/\W+/g, "-")}`;
  const expansions = tokens
    .map((t) => aliases.find((a) => a.name === t && a.address))
    .filter((a): a is { name: string; address?: string | null } => Boolean(a));

  return (
    <label className="block text-xs font-medium text-slate-500">
      {label}
      <div className="mt-1 flex flex-wrap items-center gap-1 rounded-md border border-slate-800 bg-slate-900 px-2 py-1.5 focus-within:border-emerald-600">
        {isEmpty ? (
          <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
            {emptyLabel}
          </span>
        ) : (
          tokens.map((t) => (
            <span
              key={t}
              className="inline-flex items-center gap-1 rounded bg-emerald-600/20 px-2 py-0.5 text-xs text-emerald-200"
            >
              {labels[t] ?? t}
              <button
                type="button"
                onMouseDown={(e) => {
                  e.preventDefault();
                  remove(t);
                }}
                className="text-emerald-300/70 hover:text-emerald-100"
                aria-label={`Remove ${labels[t] ?? t}`}
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))
        )}
        <input
          value={draft}
          list={listId}
          placeholder={isEmpty ? placeholder : "add…"}
          onChange={(e) => {
            const v = e.target.value;
            if (v.endsWith(",")) commit(v.slice(0, -1));
            else setDraft(v);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              commit(draft);
            } else if (e.key === "Backspace" && !draft && !isEmpty && tokens.length) {
              remove(tokens[tokens.length - 1]);
            }
          }}
          onBlur={() => commit(draft)}
          className="min-w-[7rem] flex-1 bg-transparent px-1 py-0.5 text-sm text-slate-100 outline-none"
        />
        <datalist id={listId}>
          {options.map((option) => (
            <option key={option} value={option} label={labels[option]} />
          ))}
        </datalist>
      </div>
      {expansions.length > 0 && (
        <div className="mt-0.5 text-[10px] text-emerald-400">
          {expansions.map((a) => `${a.name} → ${a.address}`).join("; ")}
        </div>
      )}
    </label>
  );
}

function Select({
  label,
  value,
  onChange,
  children,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
}) {
  if (!label) {
    return (
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-600"
      >
        {children}
      </select>
    );
  }
  return (
    <label className="block text-xs font-medium text-slate-500">
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-1 w-full rounded-md border border-slate-800 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-emerald-600"
      >
        {children}
      </select>
    </label>
  );
}

function Checkbox({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="inline-flex items-center gap-2 text-sm text-slate-300">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="h-4 w-4 rounded border-slate-700 bg-slate-900 text-emerald-600"
      />
      {label}
    </label>
  );
}

function Tab({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded border px-2.5 py-0.5 text-xs transition-colors ${
        active
          ? "border-slate-600 bg-slate-800 text-slate-100"
          : "border-slate-800 text-slate-400 hover:bg-slate-900 hover:text-slate-200"
      }`}
    >
      {label}
    </button>
  );
}
