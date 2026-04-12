import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Plus, Search, Wifi, WifiOff, AlertTriangle } from "lucide-react";
import { api } from "../lib/api";
import type { Instance } from "../lib/types";
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

  const filtered = instances.filter(
    (i) =>
      i.name.toLowerCase().includes(search.toLowerCase()) ||
      (i.location ?? "").toLowerCase().includes(search.toLowerCase()) ||
      (i.tags ?? []).some((t) => t.toLowerCase().includes(search.toLowerCase())),
  );

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Instances</h1>
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500"
        >
          <Plus className="h-4 w-4" /> Hinzufuegen
        </button>
      </div>

      {/* Search */}
      <div className="relative mt-4 max-w-md">
        <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
        <input
          type="text"
          placeholder="Suche nach Name, Standort, Tag…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full rounded-lg border border-slate-700 bg-slate-800 py-2 pl-9 pr-3 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
        />
      </div>

      {/* Grid */}
      {isLoading ? (
        <p className="mt-8 text-slate-500">Laden…</p>
      ) : filtered.length === 0 ? (
        <p className="mt-8 text-slate-500">
          {instances.length === 0
            ? 'Noch keine Instanzen. Klick "Hinzufuegen".'
            : "Kein Treffer."}
        </p>
      ) : (
        <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {filtered.map((inst) => (
            <InstanceCard
              key={inst.id}
              instance={inst}
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
  onEdit,
  onDelete,
}: {
  instance: Instance;
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
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2">
          {statusIcon}
          <h3 className="font-medium">{inst.name}</h3>
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
          Letzter Poll:{" "}
          {new Date(inst.last_success_at).toLocaleString("de-DE")}
        </p>
      )}

      {/* Actions */}
      <div className="mt-3 flex items-center gap-2 border-t border-slate-800 pt-3">
        <TestConnectionButton instanceId={inst.id} />
        <button
          onClick={onEdit}
          className="rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-800 hover:text-slate-200"
        >
          Bearbeiten
        </button>
        <button
          onClick={onDelete}
          className="rounded-md px-2 py-1 text-xs text-red-400 hover:bg-slate-800 hover:text-red-300"
        >
          Loeschen
        </button>
      </div>
    </div>
  );
}
