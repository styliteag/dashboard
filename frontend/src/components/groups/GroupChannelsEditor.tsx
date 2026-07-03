import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Trash2 } from "lucide-react";
import { api, apiErrorText } from "../../lib/api";
import type { GroupChannel, GroupChannelKind } from "../../lib/types";

/** Mirrors backend notifications/channel_config.py — field names, secrets, labels. */
const CHANNEL_SPECS: {
  channel: GroupChannelKind;
  title: string;
  fields: { name: string; label: string; secret?: boolean; required?: boolean }[];
}[] = [
  {
    channel: "mattermost",
    title: "Mattermost",
    fields: [{ name: "url", label: "Webhook URL", secret: true, required: true }],
  },
  {
    channel: "telegram",
    title: "Telegram",
    fields: [
      { name: "token", label: "Bot token", secret: true, required: true },
      { name: "chat_id", label: "Chat ID", required: true },
    ],
  },
  {
    channel: "email",
    title: "Email",
    fields: [
      { name: "smtp_host", label: "SMTP host", required: true },
      { name: "smtp_port", label: "SMTP port" },
      { name: "security", label: "Security (starttls | ssl | none)" },
      { name: "from", label: "From address", required: true },
      { name: "to", label: "Recipients", required: true },
      { name: "username", label: "SMTP username" },
      { name: "password", label: "SMTP password", secret: true },
    ],
  },
];

function ChannelCard({
  groupId,
  spec,
  configured,
}: {
  groupId: number;
  spec: (typeof CHANNEL_SPECS)[number];
  configured: GroupChannel | undefined;
}) {
  const qc = useQueryClient();
  const [form, setForm] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  // Seed the form from the (masked) server config whenever it changes.
  useEffect(() => {
    setForm(configured?.config ?? {});
  }, [configured]);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["group-channels", groupId] });

  const saveMut = useMutation({
    mutationFn: () =>
      api.put<GroupChannel>(`/api/groups/${groupId}/channels/${spec.channel}`, { config: form }),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e) => setError(apiErrorText(e, "Failed to save channel")),
  });

  const removeMut = useMutation({
    mutationFn: () => api.del(`/api/groups/${groupId}/channels/${spec.channel}`),
    onSuccess: () => {
      setError(null);
      setForm({});
      invalidate();
    },
    onError: (e) => setError(apiErrorText(e, "Failed to remove channel")),
  });

  const requiredMissing = spec.fields.some((f) => f.required && !(form[f.name] ?? "").trim());

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
      <div className="flex items-center justify-between">
        <h5 className="text-xs font-semibold text-slate-200">{spec.title}</h5>
        {configured ? (
          <span className="rounded bg-emerald-600/20 px-1.5 py-0.5 text-[10px] text-emerald-400">
            configured — replaces global
          </span>
        ) : (
          <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-500">
            using global
          </span>
        )}
      </div>
      <div className="mt-2 space-y-2">
        {spec.fields.map((f) => (
          <div key={f.name} className="space-y-0.5">
            <label className="text-[10px] text-slate-500">
              {f.label}
              {f.required ? " *" : ""}
            </label>
            <input
              type={f.secret ? "password" : "text"}
              value={form[f.name] ?? ""}
              onChange={(e) => setForm((prev) => ({ ...prev, [f.name]: e.target.value }))}
              className="w-full rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 focus:border-emerald-600 focus:outline-none"
            />
          </div>
        ))}
      </div>
      {error && (
        <div className="mt-2 rounded bg-red-900/40 px-2 py-1 text-[11px] text-red-300">{error}</div>
      )}
      <div className="mt-2 flex items-center justify-end gap-1">
        {configured && (
          <button
            type="button"
            disabled={removeMut.isPending}
            onClick={() => removeMut.mutate()}
            className="inline-flex items-center gap-1 rounded px-2 py-1 text-[11px] text-red-400 hover:bg-slate-800 disabled:opacity-50"
            title="Remove — this group falls back to the global channel"
          >
            <Trash2 className="h-3 w-3" /> Remove
          </button>
        )}
        <button
          type="button"
          disabled={saveMut.isPending || requiredMissing}
          onClick={() => saveMut.mutate()}
          className="inline-flex items-center gap-1 rounded bg-emerald-600 px-2 py-1 text-[11px] font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
        >
          <Check className="h-3 w-3" /> Save
        </button>
      </div>
    </div>
  );
}

export default function GroupChannelsEditor({ groupId }: { groupId: number }) {
  const { data: channels = [] } = useQuery({
    queryKey: ["group-channels", groupId],
    queryFn: () => api.get<GroupChannel[]>(`/api/groups/${groupId}/channels`),
  });
  const byChannel = new Map(channels.map((c) => [c.channel, c]));

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
      <p className="text-[11px] text-slate-500">
        A configured channel replaces the global target for this group&apos;s instances; unconfigured
        channels fall back to the global one. Routing rules and mute toggles stay global. Saved
        secrets show as <code>••••••</code> — leave them untouched to keep the stored value.
      </p>
      <div className="mt-2 grid gap-3 md:grid-cols-3">
        {CHANNEL_SPECS.map((spec) => (
          <ChannelCard
            key={spec.channel}
            groupId={groupId}
            spec={spec}
            configured={byChannel.get(spec.channel)}
          />
        ))}
      </div>
    </div>
  );
}
