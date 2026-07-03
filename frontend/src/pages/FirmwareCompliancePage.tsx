import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Package, AlertTriangle, CheckCircle, HelpCircle, Search, Download, Lock } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import { useAgentModeMap } from "../lib/instances";
import { useAuth, canWrite } from "../lib/use-auth";
import { WebUiIconLink } from "../components/WebUiIconLink";
import { useSort, type Accessors } from "../lib/use-sort";
import SortHeader from "../components/SortHeader";
import KpiTile from "../components/KpiTile";

interface FirmwareEntry {
  instance_id: number;
  instance_name: string;
  location: string | null;
  product_version: string;
  branch?: string; // pfSense update branch / software train
  product_latest: string;
  upgrade_available: boolean;
  check_failed?: boolean; // update check could not run — verdict unknown
  updates_available: number;
  status_msg: string;
  needs_reboot: boolean;
  last_check: string;
  firmware_locked: boolean;
}

const FW_ACCESSORS: Accessors<FirmwareEntry> = {
  status: (e) => (e.product_version === "?" || e.check_failed ? 2 : e.upgrade_available ? 0 : 1),
  instance: (e) => e.instance_name.toLowerCase(),
  location: (e) => (e.location ?? "").toLowerCase(),
  installed: (e) => e.product_version,
  branch: (e) => (e.branch ?? "").toLowerCase(),
  latest: (e) => e.product_latest,
  updates: (e) => e.updates_available,
  last_check: (e) => e.last_check,
};

interface FirmwareComplianceResponse {
  instances: FirmwareEntry[];
  total: number;
  up_to_date: number;
  outdated: number;
  unknown: number;
}

interface BulkResult {
  instance_id: number;
  instance_name: string;
  success: boolean;
  message: string;
}

interface BulkActionResponse {
  results: BulkResult[];
  total: number;
  succeeded: number;
  failed: number;
}

export default function FirmwareCompliancePage() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "outdated" | "current" | "unknown">("all");
  const agentMode = useAgentModeMap();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const canWr = canWrite(user);

  const { data, isLoading } = useQuery({
    queryKey: ["firmware-compliance"],
    queryFn: () => api.get<FirmwareComplianceResponse>("/api/firmware/compliance"),
    refetchInterval: 300_000,
  });

  // Bulk update selection — only rows with a pending upgrade are eligible.
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [confirmBulk, setConfirmBulk] = useState(false);
  const [confirmText, setConfirmText] = useState("");
  const [bulkResult, setBulkResult] = useState<BulkActionResponse | null>(null);
  const [bulkError, setBulkError] = useState<string | null>(null);

  const toggleSelect = (id: number) => {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const bulkUpdateMut = useMutation({
    mutationFn: (ids: number[]) =>
      api.post<BulkActionResponse>("/api/bulk/action", {
        instance_ids: ids,
        action: "firmware_update",
      }),
    onSuccess: (res) => {
      setBulkResult(res);
      setBulkError(null);
      setConfirmBulk(false);
      setConfirmText("");
      setSelected(new Set());
      setTimeout(
        () => queryClient.invalidateQueries({ queryKey: ["firmware-compliance"] }),
        30_000,
      );
    },
    onError: (e) => {
      setBulkError(apiErrorText(e, "Bulk update failed"));
    },
  });

  const filtered = (data?.instances ?? []).filter((e) => {
    const matchSearch =
      e.instance_name.toLowerCase().includes(search.toLowerCase()) ||
      (e.location ?? "").toLowerCase().includes(search.toLowerCase());
    const matchFilter =
      filter === "all" ||
      (filter === "outdated" && e.upgrade_available) ||
      (filter === "current" && !e.upgrade_available && !e.check_failed && e.product_version !== "?") ||
      (filter === "unknown" && e.product_version === "?");
    return matchSearch && matchFilter;
  });

  const { sorted, sort, toggle } = useSort(filtered, FW_ACCESSORS);

  const hasBranch = sorted.some((e) => !!e.branch);

  // "Update all" acts on the intersection of selection and currently visible
  // rows, so filtering down never fires updates on hidden instances.
  const eligible = sorted.filter((e) => e.upgrade_available && !e.firmware_locked);
  const selectedEligible = eligible.filter((e) => selected.has(e.instance_id));
  const allEligibleSelected = eligible.length > 0 && selectedEligible.length === eligible.length;
  const toggleSelectAll = () =>
    setSelected(allEligibleSelected ? new Set() : new Set(eligible.map((e) => e.instance_id)));

  return (
    <div>
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <Package className="h-5 w-5 text-slate-400" /> Firmware compliance
      </h1>

      {data && (
        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          <KpiTile label="Total" value={data.total} color="text-slate-100" />
          <KpiTile label="Up to date" value={data.up_to_date} color="text-emerald-400" />
          <KpiTile label="Outdated" value={data.outdated} color="text-amber-400" />
          <KpiTile label="Unknown" value={data.unknown} color="text-slate-500" />
        </div>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 py-2 pl-9 pr-3 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </div>
        {(["all", "outdated", "current", "unknown"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`rounded-md px-3 py-1.5 text-xs ${
              filter === f ? "bg-emerald-600 text-white" : "text-slate-400 hover:bg-slate-800"
            }`}
          >
            {{ all: "All", outdated: "Outdated", current: "Up to date", unknown: "Unknown" }[f]}
          </button>
        ))}
        {canWr && selectedEligible.length > 0 && !confirmBulk && (
          <button
            onClick={() => setConfirmBulk(true)}
            className="ml-auto flex items-center gap-1 rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-amber-500"
          >
            <Download className="h-3.5 w-3.5" /> Update {selectedEligible.length} selected
          </button>
        )}
      </div>

      {/* Bulk update confirmation */}
      {confirmBulk && (
        <div className="mt-3 rounded-lg border border-red-800/50 bg-red-900/20 p-3">
          <p className="text-sm text-red-300">
            This starts a firmware update on {selectedEligible.length} instance
            {selectedEligible.length > 1 ? "s" : ""} — each box reboots when its update requires
            it. Type <span className="font-mono font-semibold">UPDATE</span> to confirm:
          </p>
          <ul className="mt-2 max-h-32 overflow-y-auto text-xs text-slate-400">
            {selectedEligible.map((e) => (
              <li key={e.instance_id}>
                {e.instance_name}: {e.product_version} → {e.product_latest}
              </li>
            ))}
          </ul>
          <div className="mt-2 flex gap-2">
            <input
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-sm"
              placeholder="UPDATE"
            />
            <button
              onClick={() => bulkUpdateMut.mutate(selectedEligible.map((e) => e.instance_id))}
              disabled={confirmText !== "UPDATE" || bulkUpdateMut.isPending}
              className="rounded bg-red-600 px-3 py-1 text-sm font-medium text-white disabled:opacity-50"
            >
              {bulkUpdateMut.isPending ? "Starting…" : "Start updates"}
            </button>
            <button
              onClick={() => {
                setConfirmBulk(false);
                setConfirmText("");
              }}
              className="text-sm text-slate-400"
            >
              Cancel
            </button>
          </div>
          {bulkError && <p className="mt-2 text-sm text-red-400">{bulkError}</p>}
        </div>
      )}

      {/* Bulk update result */}
      {bulkResult && (
        <div className="mt-3 rounded-lg border border-slate-700 bg-slate-900/60 p-3">
          <p className="text-sm">
            <span className="text-emerald-400">{bulkResult.succeeded} started</span>
            {bulkResult.failed > 0 && (
              <span className="text-red-400">, {bulkResult.failed} failed</span>
            )}
            <button
              onClick={() => setBulkResult(null)}
              className="ml-3 text-xs text-slate-500 hover:text-slate-300"
            >
              Dismiss
            </button>
          </p>
          <ul className="mt-1 text-xs text-slate-400">
            {bulkResult.results.map((r) => (
              <li key={r.instance_id}>
                {r.success ? "✓" : "✗"} {r.instance_name}
                {!r.success && <span className="text-red-400"> — {r.message}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {isLoading ? (
        <p className="mt-6 text-slate-500">Loading firmware status of all instances…</p>
      ) : (
        <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                {canWr && (
                  <th className="px-3 py-2">
                    <input
                      type="checkbox"
                      checked={allEligibleSelected}
                      onChange={toggleSelectAll}
                      disabled={eligible.length === 0}
                      title="Select all visible with pending update"
                    />
                  </th>
                )}
                <SortHeader label="Status" colKey="status" sort={sort} toggle={toggle} />
                <SortHeader label="Instance" colKey="instance" sort={sort} toggle={toggle} />
                <SortHeader label="Location" colKey="location" sort={sort} toggle={toggle} />
                <SortHeader label="Installed" colKey="installed" sort={sort} toggle={toggle} />
                {hasBranch && (
                  <SortHeader label="Branch" colKey="branch" sort={sort} toggle={toggle} />
                )}
                <SortHeader label="Latest" colKey="latest" sort={sort} toggle={toggle} />
                <SortHeader label="Updates" colKey="updates" sort={sort} toggle={toggle} />
                <SortHeader label="Last check" colKey="last_check" sort={sort} toggle={toggle} />
              </tr>
            </thead>
            <tbody>
              {sorted.map((e) => (
                <tr key={e.instance_id} className="border-t border-slate-800">
                  {canWr && (
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        checked={selected.has(e.instance_id)}
                        onChange={() => toggleSelect(e.instance_id)}
                        disabled={!e.upgrade_available || e.firmware_locked}
                        title={
                          e.firmware_locked
                            ? "Firmware updates locked for this instance"
                            : e.upgrade_available
                              ? "Select for update"
                              : "No update pending"
                        }
                      />
                    </td>
                  )}
                  <td className="px-3 py-2">
                    {e.product_version === "?" ? (
                      <HelpCircle className="h-4 w-4 text-slate-500" />
                    ) : e.upgrade_available ? (
                      <AlertTriangle className="h-4 w-4 text-amber-400" />
                    ) : e.check_failed ? (
                      <span title="Update check failed — status unknown">
                        <HelpCircle className="h-4 w-4 text-amber-400" />
                      </span>
                    ) : (
                      <CheckCircle className="h-4 w-4 text-emerald-400" />
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <Link
                        to={`/instances/${e.instance_id}`}
                        className="text-emerald-400 hover:underline"
                      >
                        {e.instance_name}
                      </Link>
                      <WebUiIconLink
                        instanceId={e.instance_id}
                        instanceName={e.instance_name}
                        agentMode={agentMode.get(e.instance_id) ?? false}
                      />
                      {e.firmware_locked && (
                        <Lock
                          className="h-3.5 w-3.5 text-red-400"
                          aria-label="Firmware updates locked"
                        />
                      )}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-slate-400">{e.location || "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs">{e.product_version}</td>
                  {hasBranch && (
                    <td className="px-3 py-2 font-mono text-xs text-slate-400">
                      {e.branch || "—"}
                    </td>
                  )}
                  <td className="px-3 py-2 font-mono text-xs">
                    {e.product_latest && e.product_latest !== e.product_version ? (
                      <span className="text-amber-400">{e.product_latest}</span>
                    ) : (
                      e.product_latest || "—"
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {e.updates_available > 0 ? (
                      <span className="text-amber-400">{e.updates_available}</span>
                    ) : (
                      <span className="text-slate-500">0</span>
                    )}
                    {e.needs_reboot && <span className="ml-1 text-xs text-red-400">(reboot)</span>}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">{e.last_check || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
