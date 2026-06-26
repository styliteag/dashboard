import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search, Download, ArrowUpCircle, List, LayoutGrid } from "lucide-react";
import { api } from "../lib/api";
import type { ConnectedAgent, Instance, Overview } from "../lib/types";
import AddInstanceDialog from "../components/AddInstanceDialog";
import EditInstanceDialog from "../components/EditInstanceDialog";
import DeleteInstanceDialog from "../components/DeleteInstanceDialog";
import { InstanceCard, InstanceRow } from "../components/InstanceViews";

export default function InstancesPage() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [editTarget, setEditTarget] = useState<Instance | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Instance | null>(null);
  const [updateMsg, setUpdateMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [view, setView] = useState<"list" | "grid">(
    () => (localStorage.getItem("instances.view") as "list" | "grid") || "list",
  );
  const setViewPersisted = (v: "list" | "grid") => {
    localStorage.setItem("instances.view", v);
    setView(v);
  };

  // Connected agents → drives the "update available" banner + Update all.
  const { data: agents = [] } = useQuery({
    queryKey: ["agents-connected"],
    queryFn: () => api.get<ConnectedAgent[]>("/api/agents/connected"),
    refetchInterval: 15_000,
  });
  const outdated = agents.filter((a) => a.update_available);
  const servedVersion = outdated[0]?.served_version ?? null;
  const agentByInstance = new Map(agents.map((a) => [a.instance_id, a]));

  const updateAllMut = useMutation({
    mutationFn: () =>
      api.post<{
        served_version: string;
        updated: {
          instance_id: number;
          instance_name: string;
          result: { success: boolean; output: string };
        }[];
      }>("/api/agents/update-all"),
    onSuccess: (data) => {
      const failed = data.updated.filter((u) => !u.result.success);
      const ok = data.updated.length - failed.length;
      if (failed.length) {
        const reason = failed[0].result.output || "rejected";
        setUpdateMsg({
          ok: false,
          text: `${ok} updating to ${data.served_version}, ${failed.length} rejected: ${reason}`,
        });
        setTimeout(() => setUpdateMsg(null), 12000);
      } else {
        setUpdateMsg({
          ok: true,
          text: `Updating ${data.updated.length} agent(s) to ${data.served_version}…`,
        });
        setTimeout(() => setUpdateMsg(null), 6000);
      }
      queryClient.invalidateQueries({ queryKey: ["agents-connected"] });
    },
  });

  const { data: instances = [], isLoading } = useQuery({
    queryKey: ["instances"],
    queryFn: () => api.get<Instance[]>("/api/instances"),
    refetchInterval: 30_000,
  });

  const { data: overview } = useQuery({
    queryKey: ["overview"],
    queryFn: () => api.get<Overview>("/api/overview"),
    refetchInterval: 30_000,
  });

  const [activeTag, setActiveTag] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulkMsg, setBulkMsg] = useState<string | null>(null);

  const toggleSelect = (id: number) => {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const selectAll = () => setSelected(new Set(filtered.map((i) => i.id)));
  const selectNone = () => setSelected(new Set());

  const bulkMut = useMutation({
    mutationFn: (action: string) =>
      api.post<{ succeeded: number; failed: number }>("/api/bulk/action", {
        instance_ids: [...selected],
        action,
      }),
    onSuccess: (data) => {
      setBulkMsg(`${data.succeeded} succeeded, ${data.failed} failed`);
      setTimeout(() => setBulkMsg(null), 5000);
    },
  });

  // Collect all unique tags across instances
  const allTags = [...new Set(instances.flatMap((i) => i.tags ?? []))].sort();

  const filtered = instances.filter((i) => {
    const matchSearch =
      !search ||
      i.name.toLowerCase().includes(search.toLowerCase()) ||
      (i.location ?? "").toLowerCase().includes(search.toLowerCase()) ||
      (i.tags ?? []).some((t) => t.toLowerCase().includes(search.toLowerCase()));
    const matchTag = !activeTag || (i.tags ?? []).includes(activeTag);
    return matchSearch && matchTag;
  });

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Instances</h1>
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500"
        >
          <Plus className="h-4 w-4" /> Add
        </button>
      </div>

      {/* KPI Tiles (US-3.4) */}
      {overview && (
        <div className="mt-4 grid gap-3 sm:grid-cols-4">
          <KpiTile label="Total" value={overview.total} color="text-slate-100" />
          <KpiTile label="Online" value={overview.online} color="text-emerald-400" />
          <KpiTile label="Degraded" value={overview.degraded} color="text-amber-400" />
          <KpiTile label="Offline" value={overview.offline} color="text-red-400" />
        </div>
      )}

      {/* Agent update banner */}
      {outdated.length > 0 && (
        <div className="mt-4 flex flex-wrap items-center gap-3 rounded-lg border border-amber-800/50 bg-amber-900/20 px-4 py-2.5">
          <ArrowUpCircle className="h-4 w-4 text-amber-400" />
          <span className="text-sm text-amber-300">
            {outdated.length} agent{outdated.length > 1 ? "s" : ""} can be updated
            {servedVersion ? ` → ${servedVersion}` : ""}
          </span>
          <button
            onClick={() => updateAllMut.mutate()}
            disabled={updateAllMut.isPending}
            className="ml-auto rounded-lg bg-amber-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-amber-500 disabled:opacity-50"
          >
            {updateAllMut.isPending ? "Updating…" : "Update all agents"}
          </button>
        </div>
      )}
      {updateMsg && (
        <div
          className={`mt-2 rounded-lg px-3 py-2 text-sm ${
            updateMsg.ok ? "bg-amber-900/40 text-amber-300" : "bg-red-900/40 text-red-300"
          }`}
        >
          {updateMsg.text}
        </div>
      )}

      {/* Search */}
      <div className="relative mt-4 max-w-md">
        <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
        <input
          type="text"
          placeholder="Search by name, location, tag…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full rounded-lg border border-slate-700 bg-slate-800 py-2 pl-9 pr-3 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
        />
      </div>

      {/* Tag filter chips */}
      {allTags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            onClick={() => setActiveTag(null)}
            className={`rounded-full px-3 py-1 text-xs ${
              !activeTag ? "bg-emerald-600 text-white" : "bg-slate-800 text-slate-400 hover:bg-slate-700"
            }`}
          >
            All
          </button>
          {allTags.map((tag) => (
            <button
              key={tag}
              onClick={() => setActiveTag(activeTag === tag ? null : tag)}
              className={`rounded-full px-3 py-1 text-xs ${
                activeTag === tag ? "bg-emerald-600 text-white" : "bg-slate-800 text-slate-400 hover:bg-slate-700"
              }`}
            >
              {tag}
            </button>
          ))}
        </div>
      )}

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="mt-4 flex items-center gap-3 rounded-lg border border-emerald-800/50 bg-emerald-900/20 px-4 py-2">
          <span className="text-sm text-emerald-300">{selected.size} selected</span>
          <button
            onClick={() => bulkMut.mutate("firmware_check")}
            disabled={bulkMut.isPending}
            className="rounded bg-slate-800 px-3 py-1 text-xs text-slate-300 hover:bg-slate-700"
          >
            Firmware check
          </button>
          <button
            onClick={() => bulkMut.mutate("ipsec_restart")}
            disabled={bulkMut.isPending}
            className="rounded bg-slate-800 px-3 py-1 text-xs text-slate-300 hover:bg-slate-700"
          >
            IPsec Restart
          </button>
          <button onClick={selectAll} className="ml-auto text-xs text-slate-400 hover:text-slate-200">
            All
          </button>
          <button onClick={selectNone} className="text-xs text-slate-400 hover:text-slate-200">
            None
          </button>
        </div>
      )}

      {bulkMsg && (
        <div className="mt-2 rounded-lg bg-emerald-900/40 px-3 py-2 text-sm text-emerald-300">{bulkMsg}</div>
      )}

      {/* View toggle + Export */}
      <div className="mt-4 flex items-center justify-between">
        <div className="inline-flex rounded-lg border border-slate-700 bg-slate-800/50 p-0.5 text-xs">
          {(["list", "grid"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setViewPersisted(v)}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 capitalize ${
                view === v ? "bg-slate-700 text-slate-100" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {v === "list" ? <List className="h-4 w-4" /> : <LayoutGrid className="h-4 w-4" />}
              {v}
            </button>
          ))}
        </div>
        <a
          href="/api/export/instances.csv"
          className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
        >
          <Download className="h-3.5 w-3.5" /> CSV Export
        </a>
      </div>

      {/* Instances: list (default) or grid */}
      {isLoading ? (
        <p className="mt-8 text-slate-500">Loading…</p>
      ) : filtered.length === 0 ? (
        <p className="mt-8 text-slate-500">
          {instances.length === 0 ? 'No instances yet. Click "Add".' : "No matches."}
        </p>
      ) : view === "grid" ? (
        <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((inst) => (
            <InstanceCard
              key={inst.id}
              instance={inst}
              agent={agentByInstance.get(inst.id)}
              selected={selected.has(inst.id)}
              onToggleSelect={() => toggleSelect(inst.id)}
              onEdit={() => setEditTarget(inst)}
              onDelete={() => setDeleteTarget(inst)}
            />
          ))}
        </div>
      ) : (
        <div className="mt-6 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">
                  <input
                    type="checkbox"
                    checked={selected.size > 0 && selected.size === filtered.length}
                    onChange={() => (selected.size === filtered.length ? selectNone() : selectAll())}
                    className="rounded border-slate-600"
                    aria-label="Select all"
                  />
                </th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Location</th>
                <th className="px-3 py-2">Agent / Mode</th>
                <th className="px-3 py-2">Tags</th>
                <th className="px-3 py-2">Last poll</th>
                <th className="px-3 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((inst) => (
                <InstanceRow
                  key={inst.id}
                  instance={inst}
                  agent={agentByInstance.get(inst.id)}
                  selected={selected.has(inst.id)}
                  onToggleSelect={() => toggleSelect(inst.id)}
                  onEdit={() => setEditTarget(inst)}
                  onDelete={() => setDeleteTarget(inst)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Dialogs */}
      {showAdd && <AddInstanceDialog onClose={() => setShowAdd(false)} />}
      {editTarget && (
        <EditInstanceDialog
          instance={editTarget}
          onClose={() => setEditTarget(null)}
        />
      )}
      {deleteTarget && (
        <DeleteInstanceDialog
          instance={deleteTarget}
          onClose={() => setDeleteTarget(null)}
        />
      )}
    </div>
  );
}

function KpiTile({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3">
      <p className="text-xs text-slate-500">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );
}
