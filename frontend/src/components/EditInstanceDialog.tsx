import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, apiErrorText } from "../lib/api";
import { deviceCaps } from "../lib/capabilities";
import { useAuth } from "../lib/use-auth";
import type { Group, Instance } from "../lib/types";
import Dialog from "./Dialog";
import TagsInput from "./TagsInput";

interface Props {
  instance: Instance;
  onClose: () => void;
}

export default function EditInstanceDialog({ instance, onClose }: Props) {
  const queryClient = useQueryClient();
  const { user: me } = useAuth();
  // Agent mode reaches the firewall through the agent (push + relay), so the
  // direct-API fields (key/secret, TLS verify) don't apply — only the agent-only
  // Auto-Login does. Mirror AddInstanceDialog's per-mode field set.
  const agentMode = instance.agent_mode;
  const isSecurepoint = instance.device_type === "securepoint";
  const caps = deviceCaps(instance.device_type);
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
    ? agentMode
      ? defaults.push_interval_seconds
      : defaults.poll_interval_seconds
    : null;
  const [form, setForm] = useState({
    name: instance.name,
    base_url: instance.base_url,
    api_key: "",
    api_secret: "",
    ssl_verify: instance.ssl_verify,
    gui_login_enabled: instance.gui_login_enabled,
    shell_enabled: instance.shell_enabled,
    ssh_enabled: instance.ssh_enabled,
    ssh_port: String(instance.ssh_port),
    ssh_user: instance.ssh_user,
    ssh_key: "",
    // One field for either cadence: push (agent) or poll (direct). Empty = inherit
    // the global default; the backend distinguishes "cleared" from "unchanged".
    interval:
      (agentMode ? instance.push_interval_seconds : instance.poll_interval_seconds)?.toString() ??
      "",
    location: instance.location ?? "",
    tags: instance.tags ?? [],
    notes: instance.notes ?? "",
    ping_url: instance.ping_url ?? "",
    maintenance: instance.maintenance,
    firmware_locked: instance.firmware_locked,
  });
  const [groupId, setGroupId] = useState(String(instance.group_id));
  const [error, setError] = useState<string | null>(null);

  // Moving between groups: admins pick among their memberships, superadmins any
  // group. Uses the dedicated move endpoint (rights operation, not config).
  const { data: allGroups } = useQuery({
    queryKey: ["groups"],
    queryFn: () => api.get<Group[]>("/api/groups"),
    enabled: !!me?.is_superadmin,
  });
  const groupOptions = me?.is_superadmin && allGroups ? allGroups : (me?.groups ?? []);
  const canMove =
    (me?.is_superadmin || me?.is_admin) &&
    groupOptions.length > 1 &&
    groupOptions.some((g) => g.id === instance.group_id);

  const set = (field: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [field]: e.target.value }));

  const mutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        name: form.name,
        // Push-only types (linux) have no base_url — the backend rejects one.
        ...(caps.directApi ? { base_url: form.base_url } : {}),
        location: form.location || null,
        notes: form.notes || null,
        tags: form.tags.length > 0 ? form.tags : null,
        // null clears the override back to the global default; a number sets it.
        [agentMode ? "push_interval_seconds" : "poll_interval_seconds"]:
          form.interval.trim() === "" ? null : Number(form.interval),
        // Out-of-band probe target; empty clears it. Maintenance is a direct toggle.
        ping_url: form.ping_url.trim(),
        maintenance: form.maintenance,
        firmware_locked: form.firmware_locked,
      };
      if (agentMode) {
        body.gui_login_enabled = form.gui_login_enabled;
      } else {
        body.ssl_verify = form.ssl_verify;
        // Only send secrets if the user typed something new (US-2.2).
        if (form.api_key) body.api_key = form.api_key;
        if (form.api_secret) body.api_secret = form.api_secret;
      }
      // Terminal opt-in (agent boxes + SSH-reachable Securepoint). Only send it when
      // actually changed — the field is admin-gated server-side, so sending it
      // unchanged would 403 a non-admin editing anything else.
      if (form.shell_enabled !== instance.shell_enabled) {
        body.shell_enabled = form.shell_enabled;
      }
      if (isSecurepoint) {
        body.ssh_enabled = form.ssh_enabled;
        body.ssh_port = Number(form.ssh_port) || 9922;
        body.ssh_user = form.ssh_user || "root";
        if (form.ssh_key) body.ssh_key = form.ssh_key; // empty = keep existing
      }
      const updated = await api.patch<Instance>(`/api/instances/${instance.id}`, body);
      if (canMove && Number(groupId) !== instance.group_id) {
        await api.put(`/api/instances/${instance.id}/group`, { group_id: Number(groupId) });
      }
      return updated;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      // Detail page reads ["instance", id]; without this the edited fields
      // (e.g. Auto-login) only show after a full page reload.
      queryClient.invalidateQueries({ queryKey: ["instance", String(instance.id)] });
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
    <Dialog title={`Edit instance: ${instance.name}`} onClose={onClose} wide>
      <form onSubmit={handleSubmit} className="space-y-3">
        {error && (
          <div className="rounded-lg bg-red-900/40 px-3 py-2 text-sm text-red-300">{error}</div>
        )}
        <Input label="Name" value={form.name} onChange={set("name")} required />
        {canMove && (
          <div className="space-y-1">
            <label className="text-xs text-slate-400">Group</label>
            <select
              value={groupId}
              onChange={(e) => setGroupId(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
            >
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
            label="Base URLs (comma-separated, all clickable)"
            value={form.base_url}
            onChange={set("base_url")}
            placeholder="https://10.0.0.1:4444, https://fw.example"
            required
          />
        )}
        {!agentMode && (
          <>
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
          </>
        )}
        <Input label="Location" value={form.location} onChange={set("location")} />
        <TagsInput value={form.tags} onChange={(tags) => setForm((f) => ({ ...f, tags }))} />
        <Input
          label="Reachability probe (ping URL or host, empty = none)"
          value={form.ping_url}
          onChange={set("ping_url")}
          placeholder="https://10.0.0.1:4444"
        />
        <label className="flex items-center gap-2 text-sm text-amber-300">
          <input
            type="checkbox"
            checked={form.maintenance}
            onChange={(e) => setForm((f) => ({ ...f, maintenance: e.target.checked }))}
            className="rounded border-slate-600"
          />
          Maintenance — cap all checks at WARN (yellow, never red); auto-clears when it reports
          healthy again
        </label>
        <label className="flex items-center gap-2 text-sm text-red-300">
          <input
            type="checkbox"
            checked={form.firmware_locked}
            onChange={(e) => setForm((f) => ({ ...f, firmware_locked: e.target.checked }))}
            className="rounded border-slate-600"
          />
          Lock firmware updates — blocks both the single-instance update and bulk &quot;Update
          all&quot; for this instance
        </label>
        <Input
          label={`${agentMode ? "Push" : "Poll"} interval, seconds (empty = global default, min 5)`}
          value={form.interval}
          onChange={set("interval")}
          type="number"
          min={5}
          placeholder={defaultInterval ? `global default: ${defaultInterval}s` : "global default"}
        />
        {!agentMode && (
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input
              type="checkbox"
              checked={!form.ssl_verify}
              onChange={(e) => setForm((f) => ({ ...f, ssl_verify: !e.target.checked }))}
              className="rounded border-slate-600"
            />
            Skip SSL verification (self-signed certs)
          </label>
        )}
        {agentMode && caps.webif && (
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input
              type="checkbox"
              checked={form.gui_login_enabled}
              onChange={(e) => setForm((f) => ({ ...f, gui_login_enabled: e.target.checked }))}
              className="rounded border-slate-600"
            />
            Auto-login — replay the firewall&apos;s WebUI login so &quot;Open GUI&quot; lands signed
            in (requires GUI proxy)
          </label>
        )}
        {(agentMode || isSecurepoint) && (
          <label className="flex items-center gap-2 text-sm text-amber-300/80">
            <input
              type="checkbox"
              checked={form.shell_enabled}
              onChange={(e) => setForm((f) => ({ ...f, shell_enabled: e.target.checked }))}
              className="rounded border-slate-600"
            />
            Terminal (root shell) — allow a browser terminal to a root shell on this box (needs the
            server-wide shell feature{isSecurepoint ? "; Securepoint uses SSH" : ""})
          </label>
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
                    SSH private key (ed25519 PEM){" "}
                    {instance.ssh_key_set ? "— leave empty to keep existing" : ""}
                  </label>
                  <textarea
                    value={form.ssh_key}
                    onChange={set("ssh_key")}
                    rows={4}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-xs font-mono focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
                    placeholder={
                      instance.ssh_key_set ? "unchanged" : "-----BEGIN OPENSSH PRIVATE KEY-----"
                    }
                  />
                </div>
              </>
            )}
          </div>
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
