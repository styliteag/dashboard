import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, apiErrorText } from "../lib/api";
import { deviceCaps } from "../lib/capabilities";
import { useAuth } from "../lib/use-auth";
import { DEVICE_TYPES, type Group, type Instance } from "../lib/types";
import Dialog from "./Dialog";

interface Props {
  onClose: () => void;
}

export default function AddInstanceDialog({ onClose }: Props) {
  const queryClient = useQueryClient();
  const { user: me } = useAuth();
  const [form, setForm] = useState({
    name: "",
    group_id: "",
    base_url: "https://",
    device_type: "opnsense",
    agent_mode: false,
    api_key: "",
    api_secret: "",
    ca_bundle: "",
    ssl_verify: true,
    ssh_enabled: false,
    ssh_port: "9922",
    ssh_user: "root",
    ssh_key: "",
    interval: "", // push (agent) or poll (direct) cadence; empty = global default
    location: "",
    notes: "",
    tags: "",
    ping_url: "", // out-of-band reachability probe target; empty = none
  });
  const [error, setError] = useState<string | null>(null);

  const isSecurepoint = form.device_type === "securepoint";
  const caps = deviceCaps(form.device_type);
  // Target group: normal users pick among their memberships (implied when they
  // have exactly one); superadmins may target any group.
  const { data: allGroups } = useQuery({
    queryKey: ["groups"],
    queryFn: () => api.get<Group[]>("/api/groups"),
    enabled: !!me?.is_superadmin,
  });
  const groupOptions = me?.is_superadmin && allGroups ? allGroups : (me?.groups ?? []);
  const needsGroupChoice = groupOptions.length > 1;
  // Global interval defaults — shown as the placeholder so "empty = inherit" is concrete.
  const { data: defaults } = useQuery({
    queryKey: ["instance-defaults"],
    queryFn: () =>
      api.get<{ poll_interval_seconds: number; push_interval_seconds: number }>(
        "/api/instances/defaults",
      ),
    staleTime: Infinity,
  });
  const defaultInterval = defaults
    ? form.agent_mode
      ? defaults.push_interval_seconds
      : defaults.poll_interval_seconds
    : null;

  const set = (field: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [field]: e.target.value }));

  // Securepoint is direct-only and ships self-signed certs: force agent off + skip
  // SSL verify. Push-only types (linux) are the inverse: agent mode is the only mode.
  const onDeviceTypeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const device_type = e.target.value;
    const nextCaps = deviceCaps(device_type);
    setForm((f) => ({
      ...f,
      device_type,
      ...(device_type === "securepoint" ? { agent_mode: false, ssl_verify: false } : {}),
      ...(!nextCaps.directApi ? { agent_mode: true } : {}),
    }));
  };

  const mutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        name: form.name,
        ...(form.group_id !== "" ? { group_id: Number(form.group_id) } : {}),
        // Push-only types (linux) have no URL/API/TLS surface at all.
        ...(caps.directApi
          ? { base_url: form.base_url, ca_bundle: form.ca_bundle || null, ssl_verify: form.ssl_verify }
          : {}),
        device_type: form.device_type,
        agent_mode: form.agent_mode,
        ...(!form.agent_mode && form.api_key ? { api_key: form.api_key } : {}),
        ...(!form.agent_mode && form.api_secret ? { api_secret: form.api_secret } : {}),
        ...(isSecurepoint
          ? {
              ssh_enabled: form.ssh_enabled,
              ssh_port: Number(form.ssh_port) || 9922,
              ssh_user: form.ssh_user || "root",
              ...(form.ssh_key ? { ssh_key: form.ssh_key } : {}),
            }
          : {}),
        ...(form.interval.trim() !== ""
          ? {
              [form.agent_mode ? "push_interval_seconds" : "poll_interval_seconds"]: Number(
                form.interval,
              ),
            }
          : {}),
        location: form.location || null,
        notes: form.notes || null,
        tags: form.tags
          ? form.tags
              .split(",")
              .map((t) => t.trim())
              .filter(Boolean)
          : null,
        ping_url: form.ping_url.trim() || null,
      };
      return api.post<Instance>("/api/instances", body);
    },
    onSuccess: async (inst) => {
      // If agent mode, auto-enable agent to generate token
      if (form.agent_mode) {
        try {
          await api.post<{ agent_token: string }>(`/api/instances/${inst.id}/agent/enable`);
          // Redirect to detail page so user sees the token
          queryClient.invalidateQueries({ queryKey: ["instances"] });
          window.location.href = `/instances/${inst.id}`;
          return;
        } catch {
          // Token generation failed, but instance was created
        }
      }
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      onClose();
    },
    onError: (err) => {
      setError(apiErrorText(err, "Failed to save."));
    },
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    mutation.mutate();
  };

  return (
    <Dialog title="Add instance" onClose={onClose} wide>
      <form onSubmit={handleSubmit} className="space-y-3">
        {error && (
          <div className="rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
        )}
        <Input label="Name *" value={form.name} onChange={set("name")} required />
        {needsGroupChoice && (
          <div className="space-y-1">
            <label className="text-xs text-slate-400">Group *</label>
            <select
              value={form.group_id}
              onChange={(e) => setForm((f) => ({ ...f, group_id: e.target.value }))}
              required
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
            >
              <option value="" disabled>
                Select a group…
              </option>
              {groupOptions.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
        )}
        {caps.directApi && (
          <Input
            label="Base URLs (comma-separated, HTTPS) *"
            value={form.base_url}
            onChange={set("base_url")}
            placeholder={isSecurepoint ? "https://host:11115" : "https://10.0.0.1:4444"}
            required
          />
        )}

        <div className="space-y-1">
          <label className="text-xs text-slate-400">Device type *</label>
          <select
            value={form.device_type}
            onChange={onDeviceTypeChange}
            className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          >
            {DEVICE_TYPES.map((d) => (
              <option key={d.value} value={d.value}>
                {d.label}
              </option>
            ))}
          </select>
        </div>

        {/* Mode toggle — only where both transports exist (Securepoint is
            direct-only, linux is push-only). */}
        {!isSecurepoint && caps.directApi && (
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setForm((f) => ({ ...f, agent_mode: false }))}
              className={`flex-1 rounded-lg py-2 text-sm ${!form.agent_mode ? "bg-emerald-600 text-white" : "bg-slate-800 text-slate-400"}`}
            >
              Polling (API key)
            </button>
            <button
              type="button"
              onClick={() => setForm((f) => ({ ...f, agent_mode: true }))}
              className={`flex-1 rounded-lg py-2 text-sm ${form.agent_mode ? "bg-emerald-600 text-white" : "bg-slate-800 text-slate-400"}`}
            >
              Agent (no API key)
            </button>
          </div>
        )}

        {!form.agent_mode && (
          <>
            <Input
              label={isSecurepoint ? "Username *" : "API Key *"}
              value={form.api_key}
              onChange={set("api_key")}
              required
              type={isSecurepoint ? "text" : "password"}
            />
            <Input
              label={isSecurepoint ? "Password *" : "API Secret *"}
              value={form.api_secret}
              onChange={set("api_secret")}
              required
              type="password"
            />
          </>
        )}
        {form.agent_mode && (
          <p className="rounded-lg bg-slate-800 px-3 py-2 text-xs text-slate-400">
            In Agent mode no API key is required. After creating the instance you receive an agent
            token to install on the device.
          </p>
        )}
        {isSecurepoint && (
          <div className="space-y-2 rounded-lg border border-slate-700 p-3">
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={form.ssh_enabled}
                onChange={(e) => setForm((f) => ({ ...f, ssh_enabled: e.target.checked }))}
                className="rounded border-slate-600"
              />
              SSH enrichment (rich IPsec via swanctl — SPIs, cookies, byte counters)
            </label>
            {form.ssh_enabled && (
              <>
                <div className="flex gap-2">
                  <Input label="SSH port" value={form.ssh_port} onChange={set("ssh_port")} />
                  <Input label="SSH user" value={form.ssh_user} onChange={set("ssh_user")} />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-slate-400">
                    SSH private key (ed25519 PEM — generate with <code>just gen-ssh-key</code>,
                    install the public half on the box)
                  </label>
                  <textarea
                    value={form.ssh_key}
                    onChange={set("ssh_key")}
                    rows={4}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-mono focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                  />
                </div>
              </>
            )}
          </div>
        )}
        <Input label="Location" value={form.location} onChange={set("location")} />
        <Input label="Tags (comma-separated)" value={form.tags} onChange={set("tags")} />
        <Input
          label="Reachability probe (ping URL or host, empty = none)"
          value={form.ping_url}
          onChange={set("ping_url")}
          placeholder="https://10.0.0.1:4444"
        />
        <Input
          label={`${form.agent_mode ? "Push" : "Poll"} interval, seconds (empty = default, min 5)`}
          value={form.interval}
          onChange={set("interval")}
          type="number"
          min={5}
          placeholder={
            // Push-only servers get a calmer class default applied by the backend.
            !caps.directApi
              ? "default for Linux: 120s"
              : defaultInterval
                ? `global default: ${defaultInterval}s`
                : "global default"
          }
        />
        {/* TLS options only affect the direct-poll path; agent mode pushes from the box. */}
        {!form.agent_mode && (
          <>
            <div className="space-y-1">
              <label className="text-xs text-slate-400">CA bundle (PEM)</label>
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
              Skip SSL verification (self-signed certs)
            </label>
          </>
        )}
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
