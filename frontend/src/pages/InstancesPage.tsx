import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Plus, Search, Wifi, WifiOff, AlertTriangle, Activity, Download } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Instance, Overview } from "../lib/types";
import AddInstanceDialog from "../components/AddInstanceDialog";
import EditInstanceDialog from "../components/EditInstanceDialog";
import DeleteInstanceDialog from "../components/DeleteInstanceDialog";
import TestConnectionButton from "../components/TestConnectionButton";

export default function InstancesPage() {
  const [search, setSearch] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [editTarget, setEditTarget] = useState<Instance | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Instance | null>(null);

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

      {/* Export */}
      <div className="mt-4 flex justify-end">
        <a
          href="/api/export/instances.csv"
          className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
        >
          <Download className="h-3.5 w-3.5" /> CSV Export
        </a>
      </div>

      {/* Grid */}
      {isLoading ? (
        <p className="mt-8 text-slate-500">Loading…</p>
      ) : filtered.length === 0 ? (
        <p className="mt-8 text-slate-500">
          {instances.length === 0
            ? 'No instances yet. Click "Add".'
            : "No matches."}
        </p>
      ) : (
        <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((inst) => (
            <InstanceCard
              key={inst.id}
              instance={inst}
              selected={selected.has(inst.id)}
              onToggleSelect={() => toggleSelect(inst.id)}
              onEdit={() => setEditTarget(inst)}
              onDelete={() => setDeleteTarget(inst)}
            />
          ))}
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

function InstanceCard({
  instance: inst,
  selected,
  onToggleSelect,
  onEdit,
  onDelete,
}: {
  instance: Instance;
  selected: boolean;
  onToggleSelect: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const statusIcon = (() => {
    if (inst.last_error_at && !inst.last_success_at) {
      return <WifiOff className="h-4 w-4 text-red-400" />;
    }
    if (
      inst.last_error_at &&
      inst.last_success_at &&
      inst.last_error_at > inst.last_success_at
    ) {
      return <AlertTriangle className="h-4 w-4 text-amber-400" />;
    }
    if (inst.last_success_at) {
      return <Wifi className="h-4 w-4 text-emerald-400" />;
    }
    return <WifiOff className="h-4 w-4 text-slate-500" />;
  })();

  return (
    <div className={`rounded-xl border p-4 shadow ${selected ? "border-emerald-600 bg-emerald-900/10" : "border-slate-800 bg-slate-900/60"}`}>
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={selected}
            onChange={onToggleSelect}
            className="rounded border-slate-600"
          />
          {statusIcon}
          <Link to={`/instances/${inst.id}`} className="font-medium hover:text-emerald-400">{inst.name}</Link>
        </div>
        {inst.tags && inst.tags.length > 0 && (
          <div className="flex gap-1">
            {inst.tags.map((t) => (
              <span
                key={t}
                className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400"
              >
                {t}
              </span>
            ))}
          </div>
        )}
      </div>

      <p className="mt-1 truncate text-xs text-slate-500">{inst.base_url}</p>
      {inst.location && (
        <p className="text-xs text-slate-500">{inst.location}</p>
      )}

      {inst.last_error_message && (
        <p className="mt-2 truncate text-xs text-red-400">
          {inst.last_error_message}
        </p>
      )}

      {inst.last_success_at && (
        <p className="mt-1 text-xs text-slate-600">
          Last poll:{" "}
          {new Date(inst.last_success_at).toLocaleString("en-US")}
        </p>
      )}

      {/* Actions */}
      <div className="mt-3 flex items-center gap-2 border-t border-slate-800 pt-3">
        <TestConnectionButton instanceId={inst.id} />
        <Link
          to={`/instances/${inst.id}`}
          className="rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200 flex items-center gap-1"
        >
          <Activity className="h-3 w-3" /> Details
        </Link>
        <button
          onClick={onEdit}
          className="rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
        >
          Edit
        </button>
        <button
          onClick={onDelete}
          className="rounded-md px-2 py-1 text-xs text-red-400 hover:bg-slate-800 hover:text-red-300"
        >
          Delete
        </button>
      </div>
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
