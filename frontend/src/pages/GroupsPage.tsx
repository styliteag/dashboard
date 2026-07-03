import { Fragment, useState } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell, Boxes, Check, FolderTree, Pencil, Plus, Trash2, X } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import { useAuth } from "../lib/use-auth";
import GroupChannelsEditor from "../components/groups/GroupChannelsEditor";
import type { Group, GroupInstance } from "../lib/types";

const GROUPS_QK = ["groups"];

export default function GroupsPage() {
  const qc = useQueryClient();
  const { user: me } = useAuth();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<number | null>(null);
  const [renameTo, setRenameTo] = useState("");
  const [channelsFor, setChannelsFor] = useState<number | null>(null);

  const { data: groups = [], isError } = useQuery({
    queryKey: GROUPS_QK,
    queryFn: () => api.get<Group[]>("/api/groups"),
    enabled: !!me?.is_superadmin,
  });

  // One flat "instance → group" assignment table: fetch every group's
  // instances in parallel and merge. Small fleets — N cheap requests are fine.
  const instanceQueries = useQueries({
    queries: groups.map((g) => ({
      queryKey: ["group-instances", g.id],
      queryFn: () => api.get<GroupInstance[]>(`/api/groups/${g.id}/instances`),
      enabled: !!me?.is_superadmin,
    })),
  });
  const assignments: { instance: GroupInstance; groupId: number }[] = groups
    .flatMap((g, i) =>
      (instanceQueries[i]?.data ?? []).map((instance) => ({ instance, groupId: g.id })),
    )
    .sort((a, b) => a.instance.name.localeCompare(b.instance.name));

  const fail = (e: unknown, fallback: string) => setError(apiErrorText(e, fallback));
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: GROUPS_QK });
    qc.invalidateQueries({ queryKey: ["group-instances"] });
  };

  const createMut = useMutation({
    mutationFn: () => api.post<Group>("/api/groups", { name: name.trim() }),
    onSuccess: () => {
      setName("");
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to create group"),
  });

  const renameMut = useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) =>
      api.patch<Group>(`/api/groups/${id}`, { name }),
    onSuccess: () => {
      setRenaming(null);
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to rename group"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => api.del(`/api/groups/${id}`),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to delete group (move its instances first)"),
  });

  const moveMut = useMutation({
    mutationFn: ({ instanceId, groupId }: { instanceId: number; groupId: number }) =>
      api.put(`/api/instances/${instanceId}/group`, { group_id: groupId }),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to move instance"),
  });

  if (!me?.is_superadmin) {
    return (
      <div className="mx-auto max-w-3xl">
        <p className="rounded-lg bg-slate-900/60 px-4 py-3 text-sm text-slate-400">
          Group management is available to superadmins only.
        </p>
      </div>
    );
  }

  const canCreate = name.trim().length > 0 && !createMut.isPending;

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <FolderTree className="h-5 w-5 text-slate-400" /> Groups
      </h1>
      <p className="mt-1 text-sm text-slate-400">
        Every instance belongs to exactly one group; users only see instances of their groups.
        Assign users on the Users page. A group can only be deleted when it holds no instances.
      </p>

      {/* Create */}
      <div className="mt-5 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <Plus className="h-4 w-4 text-slate-400" /> Add group
        </h3>
        <div className="mt-3 flex items-center gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && canCreate) createMut.mutate();
            }}
            placeholder="Group name"
            maxLength={64}
            className="w-64 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
          <button
            type="button"
            onClick={() => createMut.mutate()}
            disabled={!canCreate}
            className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            <Plus className="h-4 w-4" /> Add
          </button>
        </div>
      </div>

      {error && (
        <div className="mt-4 rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
      )}
      {isError && (
        <div className="mt-4 rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">
          Failed to load groups.
        </div>
      )}

      {/* Group list */}
      <table className="mt-4 w-full text-sm">
        <thead className="text-left text-xs text-slate-500">
          <tr>
            <th className="py-1">Group</th>
            <th className="py-1">Members</th>
            <th className="py-1">Instances</th>
            <th className="py-1 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {groups.map((g) => (
            <Fragment key={g.id}>
              <tr className="border-t border-slate-800">
              <td className="py-2">
                {renaming === g.id ? (
                  <span className="inline-flex items-center gap-1">
                    <input
                      value={renameTo}
                      onChange={(e) => setRenameTo(e.target.value)}
                      maxLength={64}
                      className="w-48 rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs focus:border-emerald-600 focus:outline-none"
                    />
                    <button
                      type="button"
                      disabled={renameTo.trim().length === 0 || renameMut.isPending}
                      onClick={() => renameMut.mutate({ id: g.id, name: renameTo.trim() })}
                      className="rounded p-1 text-emerald-400 hover:bg-slate-800 disabled:opacity-50"
                    >
                      <Check className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => setRenaming(null)}
                      className="rounded p-1 text-slate-400 hover:bg-slate-800"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </span>
                ) : (
                  <span className="font-medium text-slate-200">{g.name}</span>
                )}
              </td>
              <td className="py-2 text-slate-400">{g.member_count}</td>
              <td className="py-2 text-slate-400">{g.instance_count}</td>
                <td className="py-2">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      type="button"
                      onClick={() => setChannelsFor(channelsFor === g.id ? null : g.id)}
                      className={`inline-flex items-center gap-1 rounded px-2 py-1 text-xs hover:bg-slate-800 ${
                        channelsFor === g.id ? "text-emerald-400" : "text-slate-300"
                      }`}
                      title="Per-group notification channels"
                    >
                      <Bell className="h-3 w-3" /> Channels
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setRenaming(g.id);
                        setRenameTo(g.name);
                      }}
                      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                    >
                      <Pencil className="h-3 w-3" /> Rename
                    </button>
                    <button
                      type="button"
                      disabled={g.instance_count > 0}
                      title={
                        g.instance_count > 0
                          ? "Move the instances out of the group first"
                          : undefined
                      }
                      onClick={() => {
                        if (window.confirm(`Delete group “${g.name}”?`)) deleteMut.mutate(g.id);
                      }}
                      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-red-400 hover:bg-slate-800 disabled:opacity-40"
                    >
                      <Trash2 className="h-3 w-3" /> Delete
                    </button>
                  </div>
                </td>
              </tr>
              {channelsFor === g.id && (
                <tr className="border-t border-slate-800/50">
                  <td colSpan={4} className="py-3">
                    <GroupChannelsEditor groupId={g.id} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>

      {/* Instance assignment — the one place to move instances between groups */}
      <div className="mt-8 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <Boxes className="h-4 w-4 text-slate-400" /> Instance assignment
        </h3>
        <p className="mt-1 text-xs text-slate-500">
          Pick a group per instance — the move applies immediately.
        </p>
        {assignments.length === 0 ? (
          <p className="mt-3 text-sm text-slate-500">No instances yet.</p>
        ) : (
          <table className="mt-3 w-full text-sm">
            <thead className="text-left text-xs text-slate-500">
              <tr>
                <th className="py-1">Instance</th>
                <th className="py-1">Group</th>
              </tr>
            </thead>
            <tbody>
              {assignments.map(({ instance, groupId }) => (
                <tr key={instance.id} className="border-t border-slate-800">
                  <td className="py-2 text-slate-200">
                    {instance.name}
                    <span className="ml-2 text-xs text-slate-500">{instance.slug}</span>
                  </td>
                  <td className="py-2">
                    <select
                      value={groupId}
                      disabled={moveMut.isPending || groups.length < 2}
                      title={groups.length < 2 ? "Create a second group first" : undefined}
                      onChange={(e) =>
                        moveMut.mutate({
                          instanceId: instance.id,
                          groupId: Number(e.target.value),
                        })
                      }
                      className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-300 focus:border-emerald-600 focus:outline-none disabled:opacity-50"
                    >
                      {groups.map((target) => (
                        <option key={target.id} value={target.id}>
                          {target.name}
                        </option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
