/**
 * A single on/off maintenance switch backed by a boolean app-setting (the
 * "Maintenance" group in the settings registry). Used at the top of each channel
 * tab to temporarily mute that channel's alerts, and on the Checkmk tab for the
 * export blackout. Reuses the shared ["app-settings"] query so it stays in sync
 * with the generic settings list.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { LucideIcon } from "lucide-react";
import { api, ApiError } from "../../lib/api";
import type { AppSettingItem } from "../../lib/types";

const QK = ["app-settings"];

function isTrue(v: string): boolean {
  return /^(true|1|yes|on)$/i.test(v.trim());
}

interface Props {
  settingKey: string;
  icon: LucideIcon;
  title: string;
  /** Sub-line shown while the toggle is ON (active). */
  activeNote: string;
  /** Sub-line shown while the toggle is OFF (idle). */
  idleNote: string;
  /** Badge text shown while ON. */
  activeBadge: string;
  /** Optional small print under the notes. */
  hint?: string;
}

export default function MuteToggle({
  settingKey,
  icon: Icon,
  title,
  activeNote,
  idleNote,
  activeBadge,
  hint,
}: Props) {
  const qc = useQueryClient();
  const { data: items = [] } = useQuery({
    queryKey: QK,
    queryFn: () => api.get<AppSettingItem[]>("/api/settings"),
  });
  const item = items.find((it) => it.key === settingKey);
  const on = item ? isTrue(item.value) : false;

  const toggleMut = useMutation({
    mutationFn: (next: boolean) =>
      api.put<AppSettingItem>("/api/settings", { key: settingKey, value: next ? "true" : "false" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: QK }),
  });

  const pending = toggleMut.isPending;

  return (
    <div
      className={`rounded-xl border p-5 ${
        on ? "border-amber-600/40 bg-amber-950/20" : "border-slate-800 bg-slate-900/60"
      }`}
    >
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <Icon className={`mt-0.5 h-5 w-5 shrink-0 ${on ? "text-amber-400" : "text-slate-400"}`} />
          <div>
            <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
            <p className="mt-0.5 text-xs text-slate-400">{on ? activeNote : idleNote}</p>
            {hint && <p className="mt-0.5 text-xs text-slate-500">{hint}</p>}
          </div>
        </div>

        <button
          type="button"
          role="switch"
          aria-checked={on}
          aria-label={title}
          disabled={pending || !item}
          onClick={() => toggleMut.mutate(!on)}
          className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:opacity-50 ${
            on ? "bg-amber-600" : "bg-slate-700"
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              on ? "translate-x-6" : "translate-x-1"
            }`}
          />
        </button>
      </div>

      {on && (
        <div className="mt-3 inline-flex items-center gap-1.5 rounded bg-amber-600/20 px-2 py-1 text-xs text-amber-300">
          <Icon className="h-3 w-3" /> {activeBadge}
        </div>
      )}
      {toggleMut.error && (
        <p className="mt-2 text-xs text-red-400">
          {toggleMut.error instanceof ApiError ? toggleMut.error.message : "Failed to update"}
        </p>
      )}
    </div>
  );
}
