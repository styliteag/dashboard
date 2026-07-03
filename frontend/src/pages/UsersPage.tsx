import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, Shield, ShieldOff, Trash2, Users as UsersIcon } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import { fmtDate } from "../lib/datetime";
import { useAuth } from "../lib/use-auth";
import type { DashUser, Group, UserRole } from "../lib/types";

const USERS_QK = ["users"];
const GROUPS_QK = ["groups"];

const ROLES: { value: UserRole; label: string; hint: string }[] = [
  { value: "admin", label: "Admin", hint: "Config + all operational actions in their groups" },
  { value: "user", label: "User", hint: "All operational actions, no configuration" },
  { value: "view_only", label: "View-Only", hint: "Reads everything, cannot change anything" },
];

const MIN_PW = 8;

export default function UsersPage() {
  const qc = useQueryClient();
  const { user: me } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("view_only");
  const [newSuperadmin, setNewSuperadmin] = useState(false);
  const [newGroups, setNewGroups] = useState<number[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [resetFor, setResetFor] = useState<number | null>(null);
  const [resetPw, setResetPw] = useState("");

  const { data: users = [], isError } = useQuery({
    queryKey: USERS_QK,
    queryFn: () => api.get<DashUser[]>("/api/users"),
    enabled: !!me?.is_superadmin,
  });
  const { data: groups = [] } = useQuery({
    queryKey: GROUPS_QK,
    queryFn: () => api.get<Group[]>("/api/groups"),
    enabled: !!me?.is_superadmin,
  });

  const fail = (e: unknown, fallback: string) => setError(apiErrorText(e, fallback));
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: USERS_QK });
    qc.invalidateQueries({ queryKey: GROUPS_QK });
  };

  const createMut = useMutation({
    mutationFn: () =>
      api.post<DashUser>("/api/users", {
        username: username.trim(),
        password,
        role,
        is_superadmin: newSuperadmin,
        group_ids: newGroups,
      }),
    onSuccess: () => {
      setUsername("");
      setPassword("");
      setRole("view_only");
      setNewSuperadmin(false);
      setNewGroups([]);
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to create user"),
  });

  const patchMut = useMutation({
    mutationFn: ({ id, body }: { id: number; body: Record<string, unknown> }) =>
      api.patch<DashUser>(`/api/users/${id}`, body),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to update user"),
  });

  const pwMut = useMutation({
    mutationFn: ({ id, new_password }: { id: number; new_password: string }) =>
      api.patch<DashUser>(`/api/users/${id}`, { new_password }),
    onSuccess: () => {
      setResetFor(null);
      setResetPw("");
      setError(null);
    },
    onError: (e) => fail(e, "Failed to reset password"),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => api.del(`/api/users/${id}`),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to delete user"),
  });

  const reset2faMut = useMutation({
    mutationFn: (id: number) => api.post(`/api/users/${id}/reset-2fa`),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e) => fail(e, "Failed to reset 2FA"),
  });

  if (!me?.is_superadmin) {
    return (
      <div className="mx-auto max-w-3xl">
        <p className="rounded-lg bg-slate-900/60 px-4 py-3 text-sm text-slate-400">
          User management is available to superadmins only.
        </p>
      </div>
    );
  }

  const toggleUserGroup = (u: DashUser, groupId: number) => {
    const current = u.groups.map((g) => g.id);
    const next = current.includes(groupId)
      ? current.filter((id) => id !== groupId)
      : [...current, groupId];
    patchMut.mutate({ id: u.id, body: { group_ids: next } });
  };

  const pwTooShort = password.length > 0 && password.length < MIN_PW;
  const canCreate = username.trim().length > 0 && password.length >= MIN_PW && !createMut.isPending;

  return (
    <div className="mx-auto max-w-5xl">
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <UsersIcon className="h-5 w-5 text-slate-400" /> Users
      </h1>
      <p className="mt-1 text-sm text-slate-400">
        Accounts, their global role and group memberships. A user only sees instances of their
        groups. <strong>SuperAdmin</strong> manages rights only (users + groups) — it grants no
        instance access by itself.
      </p>

      {/* Create */}
      <div className="mt-5 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
          <Plus className="h-4 w-4 text-slate-400" /> Add user
        </h3>
        <div className="mt-3 flex flex-wrap items-start gap-2">
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username"
            className="w-44 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
          <div className="flex flex-col">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={`Password (min ${MIN_PW})`}
              className="w-52 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
            />
            {pwTooShort && (
              <span className="mt-1 text-xs text-amber-400">
                At least {MIN_PW} characters required.
              </span>
            )}
          </div>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          >
            {ROLES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
          <label className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={newSuperadmin}
              onChange={(e) => setNewSuperadmin(e.target.checked)}
              className="accent-emerald-600"
            />
            SuperAdmin
          </label>
          <button
            type="button"
            onClick={() => createMut.mutate()}
            disabled={!canCreate}
            className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            <Plus className="h-4 w-4" /> Add
          </button>
        </div>
        {groups.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-slate-500">Groups:</span>
            {groups.map((g) => (
              <label
                key={g.id}
                className="inline-flex cursor-pointer items-center gap-1 rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-xs text-slate-300"
              >
                <input
                  type="checkbox"
                  checked={newGroups.includes(g.id)}
                  onChange={() =>
                    setNewGroups((prev) =>
                      prev.includes(g.id) ? prev.filter((id) => id !== g.id) : [...prev, g.id],
                    )
                  }
                  className="accent-emerald-600"
                />
                {g.name}
              </label>
            ))}
          </div>
        )}
        <p className="mt-2 text-xs text-slate-500">{ROLES.find((r) => r.value === role)?.hint}</p>
      </div>

      {error && (
        <div className="mt-4 rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
      )}
      {isError && (
        <div className="mt-4 rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">
          Failed to load users.
        </div>
      )}

      {/* List */}
      <table className="mt-4 w-full text-sm">
        <thead className="text-left text-xs text-slate-500">
          <tr>
            <th className="py-1">User</th>
            <th className="py-1">Role</th>
            <th className="py-1">SuperAdmin</th>
            <th className="py-1">Groups</th>
            <th className="py-1">2FA</th>
            <th className="py-1">Created</th>
            <th className="py-1 text-right">Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const isSelf = u.id === me.id;
            const memberIds = new Set(u.groups.map((g) => g.id));
            return (
              <tr key={u.id} className="border-t border-slate-800 align-top">
                <td className="py-2">
                  <span className={u.disabled ? "text-slate-500 line-through" : undefined}>
                    {u.username}
                  </span>
                  {isSelf && <span className="ml-1 text-xs text-slate-500">(you)</span>}
                  {u.disabled && (
                    <span
                      className="ml-2 rounded bg-amber-600/20 px-1.5 py-0.5 text-[10px] text-amber-400"
                      title="Logins rejected. Bootstrap seeds retire automatically once a real counterpart exists (…_DISABLED=auto) or are forced off with …_DISABLED=1; set …_DISABLED=0 to re-enable."
                    >
                      disabled
                    </span>
                  )}
                </td>
                <td className="py-2">
                  <select
                    value={u.role}
                    disabled={patchMut.isPending}
                    onChange={(e) =>
                      patchMut.mutate({ id: u.id, body: { role: e.target.value as UserRole } })
                    }
                    className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs focus:border-emerald-600 focus:outline-none disabled:opacity-50"
                  >
                    {ROLES.map((r) => (
                      <option key={r.value} value={r.value}>
                        {r.label}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="py-2">
                  <label
                    className="inline-flex items-center gap-1 text-xs text-slate-300"
                    title={isSelf ? "You cannot revoke your own superadmin flag" : undefined}
                  >
                    <input
                      type="checkbox"
                      checked={u.is_superadmin}
                      disabled={isSelf || patchMut.isPending}
                      onChange={(e) =>
                        patchMut.mutate({ id: u.id, body: { is_superadmin: e.target.checked } })
                      }
                      className="accent-emerald-600 disabled:opacity-50"
                    />
                    {u.is_superadmin && <Shield className="h-3 w-3 text-emerald-400" />}
                  </label>
                </td>
                <td className="py-2">
                  <div className="flex max-w-56 flex-wrap gap-1">
                    {groups.map((g) => (
                      <label
                        key={g.id}
                        className={`inline-flex cursor-pointer items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] ${
                          memberIds.has(g.id)
                            ? "border-emerald-700 bg-emerald-900/40 text-emerald-300"
                            : "border-slate-700 bg-slate-800 text-slate-400"
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={memberIds.has(g.id)}
                          disabled={patchMut.isPending}
                          onChange={() => toggleUserGroup(u, g.id)}
                          className="hidden"
                        />
                        {g.name}
                      </label>
                    ))}
                  </div>
                </td>
                <td className="py-2 text-xs">
                  {u.totp_enabled ? (
                    <span className="text-emerald-400">TOTP</span>
                  ) : (
                    <span className="text-slate-500">passkey/none</span>
                  )}
                </td>
                <td className="py-2 text-xs text-slate-400">{fmtDate(u.created_at)}</td>
                <td className="py-2">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      type="button"
                      onClick={() => {
                        setResetFor(resetFor === u.id ? null : u.id);
                        setResetPw("");
                      }}
                      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                    >
                      <KeyRound className="h-3 w-3" /> Reset password
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (window.confirm(`Reset 2FA for “${u.username}”? They must re-enroll.`))
                          reset2faMut.mutate(u.id);
                      }}
                      className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-amber-400 hover:bg-slate-800"
                    >
                      <ShieldOff className="h-3 w-3" /> Reset 2FA
                    </button>
                    {!isSelf && (
                      <button
                        type="button"
                        onClick={() => {
                          if (window.confirm(`Delete user “${u.username}”?`))
                            deleteMut.mutate(u.id);
                        }}
                        className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-red-400 hover:bg-slate-800"
                      >
                        <Trash2 className="h-3 w-3" /> Delete
                      </button>
                    )}
                  </div>
                  {resetFor === u.id && (
                    <div className="mt-2 flex items-center justify-end gap-2">
                      <input
                        type="password"
                        value={resetPw}
                        onChange={(e) => setResetPw(e.target.value)}
                        placeholder={`New password (min ${MIN_PW})`}
                        className="w-52 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-xs focus:border-emerald-600 focus:outline-none"
                      />
                      <button
                        type="button"
                        disabled={resetPw.length < MIN_PW || pwMut.isPending}
                        onClick={() => pwMut.mutate({ id: u.id, new_password: resetPw })}
                        className="rounded-lg bg-emerald-600 px-3 py-1 text-xs font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
                      >
                        Save
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
