import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import type { Instance } from "../lib/types";
import Dialog from "./Dialog";

interface Props {
  onClose: () => void;
}

export default function AddInstanceDialog({ onClose }: Props) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState({
    name: "",
    base_url: "https://",
    api_key: "",
    api_secret: "",
    ca_bundle: "",
    ssl_verify: true,
    location: "",
    notes: "",
    tags: "",
  });
  const [error, setError] = useState<string | null>(null);

  const set = (field: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [field]: e.target.value }));

  const mutation = useMutation({
    mutationFn: async () => {
      const body = {
        name: form.name,
        base_url: form.base_url,
        api_key: form.api_key,
        api_secret: form.api_secret,
        ca_bundle: form.ca_bundle || null,
        ssl_verify: form.ssl_verify,
        location: form.location || null,
        notes: form.notes || null,
        tags: form.tags
          ? form.tags.split(",").map((t) => t.trim()).filter(Boolean)
          : null,
      };
      return api.post<Instance>("/api/instances", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      onClose();
    },
    onError: (err) => {
      setError(err instanceof ApiError ? err.message : "Fehler beim Speichern.");
    },
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    mutation.mutate();
  };

  return (
    <Dialog title="Instanz hinzufuegen" onClose={onClose} wide>
      <form onSubmit={handleSubmit} className="space-y-3">
        {error && (
          <div className="rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
        )}
        <Input label="Name *" value={form.name} onChange={set("name")} required />
        <Input label="Base-URL (HTTPS) *" value={form.base_url} onChange={set("base_url")} required />
        <Input label="API Key *" value={form.api_key} onChange={set("api_key")} required type="password" />
        <Input label="API Secret *" value={form.api_secret} onChange={set("api_secret")} required type="password" />
        <Input label="Standort" value={form.location} onChange={set("location")} />
        <Input label="Tags (kommasepariert)" value={form.tags} onChange={set("tags")} />
        <div className="space-y-1">
          <label className="text-xs text-slate-400">CA-Bundle (PEM)</label>
          <textarea
            value={form.ca_bundle}
            onChange={set("ca_bundle")}
            rows={3}
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-mono focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
            placeholder="-----BEGIN CERTIFICATE-----"
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-400">
          <input
            type="checkbox"
            checked={!form.ssl_verify}
            onChange={(e) => setForm((f) => ({ ...f, ssl_verify: !e.target.checked }))}
            className="rounded border-slate-600"
          />
          SSL-Pruefung ueberspringen (Self-Signed Certs)
        </label>
        <div className="space-y-1">
          <label className="text-xs text-slate-400">Notizen</label>
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
            Abbrechen
          </button>
          <button
            type="submit"
            disabled={mutation.isPending}
            className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            {mutation.isPending ? "…" : "Speichern"}
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
