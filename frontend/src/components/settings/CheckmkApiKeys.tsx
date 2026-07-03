import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Eye, KeyRound, Plus, Trash2 } from "lucide-react";
import { api, apiErrorText } from "../../lib/api";
import { fmtDate, fmtDateTime, fmtRelative } from "../../lib/datetime";
import { useAuth } from "../../lib/use-auth";
import type { ApiKey, ApiKeyCreated, ApiKeyRevealed, Group } from "../../lib/types";

const KEYS_QK = ["apikeys"];

function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard blocked — user can select manually */
        }
      }}
      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
    >
      <Copy className="h-3 w-3" /> {done ? "Copied" : label}
    </button>
  );
}

export default function CheckmkApiKeys() {
  const qc = useQueryClient();
  const { user: me } = useAuth();
  const [name, setName] = useState("checkmk");
  const [bindGroups, setBindGroups] = useState<number[]>([]);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [revealed, setRevealed] = useState<Record<number, string>>({});
  const [error, setError] = useState<string | null>(null);

  const { data: keys = [] } = useQuery({
    queryKey: KEYS_QK,
    queryFn: () => api.get<ApiKey[]>("/api/apikeys"),
  });
  // Binding options: superadmins may pick any group (or none = global);
  // group-scoped admins must bind to their own groups.
  const { data: allGroups } = useQuery({
    queryKey: ["groups"],
    queryFn: () => api.get<Group[]>("/api/groups"),
    enabled: !!me?.is_superadmin,
  });
  const groupOptions = me?.is_superadmin && allGroups ? allGroups : (me?.groups ?? []);
  const bindingRequired = !me?.is_superadmin;
  const myGroupIds = new Set((me?.groups ?? []).map((g) => g.id));
  const mayReveal = (k: ApiKey) =>
    !!me?.is_superadmin || (k.groups.length > 0 && k.groups.every((g) => myGroupIds.has(g.id)));

  const createMut = useMutation({
    mutationFn: () =>
      api.post<ApiKeyCreated>("/api/apikeys", {
        name: name.trim(),
        revealable: true,
        group_ids: bindGroups,
      }),
    onSuccess: (k) => {
      setCreated(k);
      setBindGroups([]);
      setError(null);
      qc.invalidateQueries({ queryKey: KEYS_QK });
    },
    onError: (e) => setError(apiErrorText(e, "Failed to create key")),
  });

  const revokeMut = useMutation({
    mutationFn: (id: number) => api.del(`/api/apikeys/${id}`),
    onSuccess: (_d, id) => {
      setRevealed((r) => {
        const n = { ...r };
        delete n[id];
        return n;
      });
      if (created && created.id === id) setCreated(null);
      qc.invalidateQueries({ queryKey: KEYS_QK });
    },
  });

  const purgeMut = useMutation({
    mutationFn: (id: number) => api.del(`/api/apikeys/${id}/purge`),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS_QK }),
    onError: (e) => setError(apiErrorText(e, "Failed to delete key")),
  });

  const purgeAllMut = useMutation({
    mutationFn: (ids: number[]) =>
      Promise.all(ids.map((id) => api.del(`/api/apikeys/${id}/purge`))),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEYS_QK }),
    onError: (e) => setError(apiErrorText(e, "Failed to delete keys")),
  });

  const reveal = async (id: number) => {
    try {
      const r = await api.get<ApiKeyRevealed>(`/api/apikeys/${id}/reveal`);
      setRevealed((m) => ({ ...m, [id]: r.key }));
    } catch (e) {
      setError(apiErrorText(e, "Failed to reveal key"));
    }
  };

  const active = keys.filter((k) => !k.revoked_at);
  const revoked = keys.filter((k) => k.revoked_at);

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
        <KeyRound className="h-4 w-4 text-slate-400" /> API keys
      </h3>
      <p className="mt-1 text-xs text-slate-400">
        Read-only service-account keys (Bearer <code className="text-slate-300">orbit_…</code>,
        rejected on non-GET). Keys created here are <strong>re-viewable</strong>: the token is kept
        encrypted so you can copy it again later. Revoking drops that copy.
      </p>

      {/* Create */}
      <div className="mt-4 flex items-center gap-2">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Key name (e.g. checkmk)"
          className="w-56 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
        />
        <button
          type="button"
          onClick={() => createMut.mutate()}
          disabled={
            createMut.isPending || !name.trim() || (bindingRequired && bindGroups.length === 0)
          }
          className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          <Plus className="h-4 w-4" /> Create key
        </button>
      </div>
      {groupOptions.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-slate-500">Bind to groups:</span>
          {groupOptions.map((g) => (
            <label
              key={g.id}
              className={`inline-flex cursor-pointer items-center gap-1 rounded-full border px-2 py-0.5 text-xs ${
                bindGroups.includes(g.id)
                  ? "border-emerald-700 bg-emerald-900/40 text-emerald-300"
                  : "border-slate-700 bg-slate-800 text-slate-400"
              }`}
            >
              <input
                type="checkbox"
                checked={bindGroups.includes(g.id)}
                onChange={() =>
                  setBindGroups((prev) =>
                    prev.includes(g.id) ? prev.filter((id) => id !== g.id) : [...prev, g.id],
                  )
                }
                className="hidden"
              />
              {g.name}
            </label>
          ))}
          <span className="text-xs text-slate-500">
            {bindingRequired
              ? "— keys must be bound to your groups"
              : bindGroups.length === 0
                ? "— none selected: global key (all instances)"
                : ""}
          </span>
        </div>
      )}

      {error && (
        <div className="mt-3 rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
      )}

      {/* Newly created — show full token + ready-to-use env snippet */}
      {created && (
        <div className="mt-4 rounded-lg border border-emerald-700/50 bg-emerald-950/30 p-3">
          <p className="text-xs font-medium text-emerald-300">
            Key “{created.name}” created. Copy it into Checkmk:
          </p>
          <div className="mt-2 flex items-center gap-2">
            <code className="flex-1 truncate rounded bg-slate-900 px-2 py-1 font-mono text-xs text-slate-200">
              {created.key}
            </code>
            <CopyButton value={created.key} />
          </div>
          <pre className="mt-2 overflow-x-auto rounded bg-slate-900 px-2 py-1 text-xs text-slate-300">
            {`ORBIT_URL=https://<dashboard>\nORBIT_API_KEY=${created.key}`}
          </pre>
        </div>
      )}

      {/* Active keys */}
      <table className="mt-4 w-full text-sm">
        <thead className="text-left text-xs text-slate-500">
          <tr>
            <th className="py-1">Name</th>
            <th className="py-1">Prefix</th>
            <th className="py-1">Groups</th>
            <th className="py-1">Created</th>
            <th className="py-1">Last used</th>
            <th className="py-1 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {active.length === 0 && (
            <tr>
              <td colSpan={6} className="py-3 text-xs text-slate-500">
                No active keys.
              </td>
            </tr>
          )}
          {active.map((k) => (
            <tr key={k.id} className="border-t border-slate-800">
              <td className="py-2">{k.name}</td>
              <td className="py-2 font-mono text-xs text-slate-400">{k.prefix}…</td>
              <td className="py-2">
                {k.groups.length === 0 ? (
                  <span className="text-xs text-slate-500" title="Sees all instances">
                    global
                  </span>
                ) : (
                  <div className="flex flex-wrap gap-1">
                    {k.groups.map((g) => (
                      <span
                        key={g.id}
                        className="rounded-full border border-slate-700 bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300"
                      >
                        {g.name}
                      </span>
                    ))}
                  </div>
                )}
              </td>
              <td className="py-2 text-xs text-slate-400">{fmtDate(k.created_at)}</td>
              <td className="py-2 text-xs text-slate-400">
                {k.last_used_at ? (
                  <span title={fmtDateTime(k.last_used_at)}>{fmtRelative(k.last_used_at)}</span>
                ) : (
                  "never"
                )}
              </td>
              <td className="py-2">
                <div className="flex items-center justify-end gap-1">
                  {k.revealable && mayReveal(k) && (
                    <button
                      type="button"
                      onClick={() => reveal(k.id)}
                      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                    >
                      <Eye className="h-3 w-3" /> Reveal
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => revokeMut.mutate(k.id)}
                    className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-red-400 hover:bg-slate-800"
                  >
                    <Trash2 className="h-3 w-3" /> Revoke
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Revealed tokens */}
      {Object.entries(revealed).map(([id, key]) => (
        <div key={id} className="mt-2 flex items-center gap-2">
          <code className="flex-1 truncate rounded bg-slate-900 px-2 py-1 font-mono text-xs text-slate-200">
            {key}
          </code>
          <CopyButton value={key} />
        </div>
      ))}

      {revoked.length > 0 && (
        <div className="mt-5">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Revoked ({revoked.length})
            </h4>
            <button
              type="button"
              onClick={() => purgeAllMut.mutate(revoked.map((k) => k.id))}
              disabled={purgeAllMut.isPending}
              className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-red-400 hover:bg-slate-800 disabled:opacity-50"
            >
              <Trash2 className="h-3 w-3" /> Delete all
            </button>
          </div>
          <table className="mt-2 w-full text-sm">
            <tbody>
              {revoked.map((k) => (
                <tr key={k.id} className="border-t border-slate-800 text-slate-500">
                  <td className="py-2">{k.name}</td>
                  <td className="py-2 font-mono text-xs">{k.prefix}…</td>
                  <td className="py-2 text-xs">
                    revoked {k.revoked_at ? fmtDate(k.revoked_at) : ""}
                  </td>
                  <td className="py-2">
                    <div className="flex items-center justify-end">
                      <button
                        type="button"
                        onClick={() => purgeMut.mutate(k.id)}
                        disabled={purgeMut.isPending}
                        className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-red-400 hover:bg-slate-800 disabled:opacity-50"
                      >
                        <Trash2 className="h-3 w-3" /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
