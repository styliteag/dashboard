import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Instance } from "../lib/types";
import Dialog from "./Dialog";

interface Props {
  instance: Instance;
  onClose: () => void;
}

export default function EditInstanceDialog({ instance, onClose }: Props) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({
    name: instance.name,
    base_url: instance.base_url,
    api_key: "",
    api_secret: "",
    ssl_verify: instance.ssl_verify,
    location: instance.location ?? "",
    tags: (instance.tags ?? []).join(", "),
    notes: instance.notes ?? "",
  });
  const [error, setError] = useState<string | null>(null);

  const set = (field: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [field]: e.target.value }));

  const mutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        name: form.name,
        base_url: form.base_url,
        ssl_verify: form.ssl_verify,
        location: form.location || null,
        notes: form.notes || null,
        tags: form.tags
          ? form.tags.split(",").map((t) => t.trim()).filter(Boolean)
          : null,
      };
      // Only send secrets if the user typed something new (US-2.2).
      if (form.api_key) body.api_key = form.api_key;
      if (form.api_secret) body.api_secret = form.api_secret;
      return api.patch<Instance>(`/api/instances/${instance.id}`, body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      onClose();
    },
    onError: (err) => {
      setError(err instanceof ApiError ? err.message : "Failed to save.");
    },
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    mutation.mutate();
  };

  return (
    <Dialog title={`Edit instance: ${instance.name}`} onClose={onClose} wide>
      <form onSubmit={handleSubmit} className="space-y-3">
        {error && (
          <div className="rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
        )}
        <Input label="Name" value={form.name} onChange={set("name")} required />
        <Input label="Base URL" value={form.base_url} onChange={set("base_url")} required />
        <Input
          label="API Key (empty = unchanged)"
          value={form.api_key}
          onChange={set("api_key")}
          type="password"
          placeholder="unchanged"
        />
        <Input
          label="API Secret (empty = unchanged)"
          value={form.api_secret}
          onChange={set("api_secret")}
          type="password"
          placeholder="unchanged"
        />
        <Input label="Location" value={form.location} onChange={set("location")} />
        <Input label="Tags (comma-separated)" value={form.tags} onChange={set("tags")} />
        <label className="flex items-center gap-2 text-sm text-slate-400">
          <input
            type="checkbox"
            checked={!form.ssl_verify}
            onChange={(e) => setForm((f) => ({ ...f, ssl_verify: !e.target.checked }))}
            className="rounded border-slate-600"
          />
          Skip SSL verification (self-signed certs)
        </label>
        <div className="space-y-1">
          <label className="text-xs text-slate-400">Notes</label>
          <textarea
            value={form.notes}
            onChange={set("notes")}
            rows={2}
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:text-slate-200"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mutation.isPending}
            className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            {mutation.isPending ? "…" : "Save"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function Input({
  label,
  type = "text",
  ...props
}: {
  label: string;
  type?: string;
} & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className="space-y-1">
      <label className="text-xs text-slate-400">{label}</label>
      <input
        type={type}
        {...props}
        className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
      />
    </div>
  );
}
