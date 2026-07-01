import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RotateCcw, SlidersHorizontal } from "lucide-react";
import { api, ApiError } from "../../lib/api";
import type { AppSettingItem } from "../../lib/types";

const QK = ["app-settings"];

function isTrue(v: string): boolean {
  return /^(true|1|yes|on)$/i.test(v.trim());
}

function groupOrder(items: AppSettingItem[]): string[] {
  const seen: string[] = [];
  for (const it of items) if (!seen.includes(it.group)) seen.push(it.group);
  return seen;
}

interface GeneralSettingsProps {
  /** Render only these setting groups (allowlist). Omit for all. */
  include?: string[];
  /** Render every group except these. Omit for none excluded. */
  exclude?: string[];
  title?: string;
  icon?: ReactNode;
  intro?: ReactNode;
}

export default function GeneralSettings({
  include,
  exclude,
  title = "General settings",
  icon = <SlidersHorizontal className="h-4 w-4 text-slate-400" />,
  intro = (
    <>
      Override the defaults that otherwise come from the environment / <code>.env</code>. Infra and
      security settings (database URL, master key, proxy hops…) stay environment-only.
    </>
  ),
}: GeneralSettingsProps = {}) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [error, setError] = useState<Record<string, string>>({});

  const { data: items = [] } = useQuery({
    queryKey: QK,
    queryFn: () => api.get<AppSettingItem[]>("/api/settings"),
  });

  const saveMut = useMutation({
    mutationFn: (v: { key: string; value: string }) => api.put<AppSettingItem>("/api/settings", v),
    onSuccess: (_d, v) => {
      setDraft((s) => {
        const n = { ...s };
        delete n[v.key];
        return n;
      });
      setError((e) => {
        const n = { ...e };
        delete n[v.key];
        return n;
      });
      qc.invalidateQueries({ queryKey: QK });
      // A channel's config drives its "configured" badge in the routing matrix.
      qc.invalidateQueries({ queryKey: ["notification-routing"] });
    },
    onError: (e, v) =>
      setError((s) => ({ ...s, [v.key]: e instanceof ApiError ? e.message : "Save failed" })),
  });

  const resetMut = useMutation({
    mutationFn: (key: string) => api.del(`/api/settings/${key}`),
    onSuccess: (_d, key) => {
      setDraft((s) => {
        const n = { ...s };
        delete n[key];
        return n;
      });
      qc.invalidateQueries({ queryKey: QK });
      qc.invalidateQueries({ queryKey: ["notification-routing"] });
    },
  });

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-slate-200">
        {icon} {title}
      </h3>
      <p className="mt-1 text-xs text-slate-400">{intro}</p>

      {groupOrder(items)
        .filter((g) => (!include || include.includes(g)) && !(exclude ?? []).includes(g))
        .map((group) => (
          <div key={group} className="mt-5">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              {group}
            </h4>
            <div className="mt-2 divide-y divide-slate-800/60">
              {items
                .filter((it) => it.group === group)
                .map((it) => {
                  // Secrets never prefill the masked value into the editable field.
                  const inputValue = it.is_secret
                    ? (draft[it.key] ?? "")
                    : (draft[it.key] ?? it.value);
                  const isDirty = it.is_secret
                    ? !!draft[it.key]
                    : draft[it.key] !== undefined && draft[it.key] !== it.value;
                  return (
                    <div key={it.key} className="flex items-start gap-4 py-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-sm text-slate-200">{it.label}</span>
                          {it.source === "db" ? (
                            <span className="rounded bg-emerald-600/20 px-1.5 py-0.5 text-[10px] text-emerald-400">
                              {it.is_secret ? "set" : "custom"}
                            </span>
                          ) : (
                            <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[10px] text-slate-400">
                              {it.is_secret ? "not set" : "default"}
                            </span>
                          )}
                          {it.restart_required && (
                            <span className="rounded bg-amber-600/20 px-1.5 py-0.5 text-[10px] text-amber-400">
                              needs restart
                            </span>
                          )}
                        </div>
                        {it.help && <p className="mt-0.5 text-xs text-slate-500">{it.help}</p>}
                        <p className="mt-0.5 font-mono text-[11px] text-slate-600">
                          {it.key}
                          {!it.is_secret && ` · default ${it.default || "—"}`}
                        </p>
                        {error[it.key] && (
                          <p className="mt-1 text-xs text-red-400">{error[it.key]}</p>
                        )}
                      </div>

                      <div className="flex shrink-0 items-center gap-2">
                        {it.type === "bool" ? (
                          <input
                            type="checkbox"
                            checked={isTrue(it.value)}
                            disabled={saveMut.isPending}
                            onChange={(e) =>
                              saveMut.mutate({
                                key: it.key,
                                value: e.target.checked ? "true" : "false",
                              })
                            }
                            className="h-4 w-4 cursor-pointer accent-emerald-600 disabled:cursor-not-allowed"
                          />
                        ) : it.options ? (
                          <select
                            value={inputValue}
                            onChange={(e) => setDraft((s) => ({ ...s, [it.key]: e.target.value }))}
                            className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
                          >
                            {it.options.map((o) => (
                              <option key={o} value={o}>
                                {o}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <input
                            type={it.is_secret ? "password" : it.type === "int" ? "number" : "text"}
                            value={inputValue}
                            min={it.min ?? undefined}
                            max={it.max ?? undefined}
                            placeholder={
                              it.is_secret
                                ? it.source === "db"
                                  ? "•••••• (set — type to replace)"
                                  : "not set"
                                : undefined
                            }
                            onChange={(e) => setDraft((s) => ({ ...s, [it.key]: e.target.value }))}
                            className={`${it.is_secret ? "w-64" : "w-28"} rounded-lg border border-slate-700 bg-slate-800 px-2 py-1.5 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600`}
                          />
                        )}
                        {it.type !== "bool" && (
                          <button
                            type="button"
                            disabled={!isDirty || saveMut.isPending}
                            onClick={() => saveMut.mutate({ key: it.key, value: inputValue })}
                            className="rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-40"
                          >
                            Save
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={it.source !== "db" || resetMut.isPending}
                          onClick={() => resetMut.mutate(it.key)}
                          title="Reset to default"
                          className="inline-flex items-center rounded-lg px-2 py-1.5 text-slate-400 hover:bg-slate-800 disabled:opacity-30"
                        >
                          <RotateCcw className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        ))}

      <p className="mt-4 text-xs text-slate-600">
        “Needs restart” settings take effect after the next backend restart; all others apply live.
      </p>
    </div>
  );
}
