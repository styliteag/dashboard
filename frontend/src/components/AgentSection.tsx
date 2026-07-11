/**
 * Agent management: enable/disable + full step-by-step installation guide.
 * Always shows the guide when agent mode is active so any admin can follow
 * the steps without needing to re-enable just to see the instructions.
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Radio, Copy, Check, RefreshCw, ChevronDown, ChevronUp } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import { fmtDateTime, fmtRelative } from "../lib/datetime";

interface AgentStatus {
  instance_id: number;
  instance_name: string;
  agent_mode: boolean;
  agent_connected: boolean;
  agent_last_seen: string | null;
  agent_version: string | null;
  served_version: string | null;
  update_available: boolean;
  gui_proxy_enabled?: boolean;
  gui_login_enabled?: boolean;
  last_update_error?: string | null;
  last_update_version?: string | null;
}

interface AgentUpdateResponse {
  sent: boolean;
  version: string;
  result: { success: boolean; output: string };
}

interface AgentTokenResponse {
  instance_id: number;
  agent_token: string;
  agent_mode: boolean;
}

interface AgentActionResponse {
  sent: boolean;
  result: { success: boolean; output: string };
}

interface EnrollCodeResponse {
  code: string;
  instance_id: number;
  expires_at: string;
}

interface Props {
  instanceId: number;
  agentMode: boolean;
  /** Switches the install guide: FreeBSD firewalls vs linux servers (§25). */
  deviceType?: string;
}

// ----- Shared primitives ----------------------------------------------------

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handle = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button
      onClick={handle}
      className="flex shrink-0 items-center gap-1 rounded px-2 py-1 text-xs text-slate-400 transition-colors hover:bg-slate-700 hover:text-slate-200"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-emerald-400" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
      <span>{copied ? "Copied" : "Copy"}</span>
    </button>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <div className="relative mt-1.5 rounded-lg border border-slate-800 bg-slate-950">
      <div className="absolute right-2 top-2">
        <CopyButton text={code} />
      </div>
      <pre className="overflow-x-auto p-3 pr-16 font-mono text-xs leading-relaxed text-slate-300">
        {code}
      </pre>
    </div>
  );
}

function Step({
  number,
  title,
  done,
  children,
}: {
  number: number;
  title: string;
  done?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="flex gap-4">
      <div
        className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${
          done ? "bg-emerald-700 text-emerald-100" : "bg-slate-800 text-slate-300"
        }`}
      >
        {done ? <Check className="h-3.5 w-3.5" /> : number}
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium text-slate-200">{title}</p>
        <div className="mt-1.5">{children}</div>
      </div>
    </div>
  );
}

// ----- Main component -------------------------------------------------------

export default function AgentSection({ instanceId, agentMode, deviceType }: Props) {
  const queryClient = useQueryClient();
  const [localToken, setLocalToken] = useState<string | null>(null);
  const [showGuide, setShowGuide] = useState(false);
  const [confirmRegen, setConfirmRegen] = useState(false);
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const [enrollCode, setEnrollCode] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const proto = window.location.protocol;
  const host = window.location.host;
  const wsProto = proto === "https:" ? "wss" : "ws";

  // Live connection status (polls every 10 s)
  const { data: status } = useQuery({
    queryKey: ["agent-status", instanceId],
    queryFn: () => api.get<AgentStatus>(`/api/instances/${instanceId}/agent/status`),
    refetchInterval: 10_000,
    enabled: agentMode,
  });

  // Retrieve persisted token from DB (so the guide works after a page reload)
  const { data: tokenData } = useQuery({
    queryKey: ["agent-token", instanceId],
    queryFn: () => api.get<{ agent_token: string }>(`/api/instances/${instanceId}/agent/token`),
    enabled: agentMode && localToken === null,
    retry: false,
  });

  const token = localToken ?? tokenData?.agent_token ?? null;
  const connected = status?.agent_connected ?? false;

  const enableMut = useMutation({
    mutationFn: () => api.post<AgentTokenResponse>(`/api/instances/${instanceId}/agent/enable`),
    onSuccess: (data) => {
      setLocalToken(data.agent_token);
      setConfirmRegen(false);
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
      queryClient.invalidateQueries({ queryKey: ["agent-token", instanceId] });
    },
    onError: (e) => setMsg({ ok: false, text: apiErrorText(e, "Error enabling agent") }),
  });

  const disableMut = useMutation({
    mutationFn: () => api.post(`/api/instances/${instanceId}/agent/disable`),
    onSuccess: () => {
      setLocalToken(null);
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
      setMsg({ ok: true, text: "Agent disabled. Back to polling mode." });
    },
  });

  const updateMut = useMutation({
    mutationFn: () => api.post<AgentUpdateResponse>(`/api/instances/${instanceId}/agent/update`),
    onSuccess: (data) => {
      setMsg({
        ok: data.result.success,
        text: data.result.success
          ? `Updating to ${data.version}: ${data.result.output}`
          : `Update failed: ${data.result.output}`,
      });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
    },
    onError: (e) => setMsg({ ok: false, text: apiErrorText(e, "Update failed") }),
  });

  const testApiMut = useMutation({
    mutationFn: () =>
      api.post<{
        ok: boolean;
        status_code: number | null;
        latency_ms: number | null;
        error: string | null;
      }>(`/api/instances/${instanceId}/relay/test`),
    onSuccess: (r) =>
      setMsg({
        ok: r.ok,
        text: r.ok
          ? `Local API OK — HTTP ${r.status_code} in ${r.latency_ms} ms`
          : `Local API call failed: ${r.error ?? "no response"}`,
      }),
    onError: (e) => setMsg({ ok: false, text: apiErrorText(e, "Test failed") }),
  });

  const guiMut = useMutation({
    mutationFn: () => api.post<{ url: string }>(`/api/instances/${instanceId}/gui/open`),
    onSuccess: (data) => {
      // The URL is a one-time auth handoff; open it in a new tab (dev cert may warn).
      window.open(data.url, "_blank", "noopener,noreferrer");
    },
    onError: (e) => setMsg({ ok: false, text: apiErrorText(e, "Could not open GUI") }),
  });

  const uninstallMut = useMutation({
    mutationFn: () => api.post<AgentActionResponse>(`/api/instances/${instanceId}/agent/uninstall`),
    onSuccess: (data) => {
      setConfirmUninstall(false);
      setLocalToken(null);
      setMsg({
        ok: data.result.success,
        text: data.result.success
          ? "Agent is removing itself; instance switched back to polling mode."
          : `Uninstall failed: ${data.result.output}`,
      });
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
    },
    onError: (e) => setMsg({ ok: false, text: apiErrorText(e, "Uninstall failed") }),
  });

  const enrollMut = useMutation({
    mutationFn: () =>
      api.post<EnrollCodeResponse>(`/api/instances/${instanceId}/agent/enroll-code`),
    onSuccess: (data) => setEnrollCode(data.code),
    onError: (e) => setMsg({ ok: false, text: apiErrorText(e, "Could not generate code") }),
  });

  const refreshMut = useMutation({
    mutationFn: () => api.post<AgentActionResponse>(`/api/instances/${instanceId}/agent/refresh`),
    onSuccess: (data) => {
      setMsg({
        ok: data.result.success,
        text: data.result.success
          ? "Fresh snapshot pushed (logs, firmware and config backup re-collected)."
          : `Refresh failed: ${data.result.output}`,
      });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
      queryClient.invalidateQueries({ queryKey: ["log-events"] });
    },
    onError: (e) => setMsg({ ok: false, text: apiErrorText(e, "Refresh failed") }),
  });

  const reconnectMut = useMutation({
    mutationFn: () => api.post<AgentActionResponse>(`/api/instances/${instanceId}/agent/reconnect`),
    onSuccess: (data) => {
      setMsg({
        ok: data.result.success,
        text: data.result.success
          ? "Agent is reconnecting; it should be back within a few seconds."
          : `Reconnect failed: ${data.result.output}`,
      });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
    },
    onError: (e) => setMsg({ ok: false, text: apiErrorText(e, "Reconnect failed") }),
  });

  // Linux servers (§25) get curl/systemd instructions and the calmer 120s
  // class default; firewalls keep fetch/rc.d and 30s.
  const linuxGuide = deviceType === "linux";

  // Pre-filled config (dashboard URL baked in). With a one-time code the agent
  // trades it for the token on first start; otherwise the token is embedded.
  const cfg = enrollCode
    ? {
        dashboard_url: `${wsProto}://${host}/api/ws/agent`,
        enroll_code: enrollCode,
        push_interval: linuxGuide ? 120 : 30,
        log_level: "INFO",
      }
    : {
        dashboard_url: `${wsProto}://${host}/api/ws/agent`,
        agent_token: token ?? "PASTE_TOKEN_HERE",
        push_interval: linuxGuide ? 120 : 30,
        log_level: "INFO",
      };

  const downloadCmds = linuxGuide
    ? [
        // /usr/local/etc is not guaranteed on Linux distros — create it for the config.
        `mkdir -p /usr/local/orbit-agent /usr/local/etc`,
        `curl -fsSo /usr/local/orbit-agent/orbit_agent.py \\`,
        `  ${proto}//${host}/api/agent/script`,
        `curl -fsSo /usr/local/orbit-agent/run-agent.sh \\`,
        `  ${proto}//${host}/api/agent/run`,
        `curl -fsSo /usr/local/orbit-agent/check_mk_agent.linux \\`,
        `  ${proto}//${host}/api/agent/checkmk`,
        `chmod 755 /usr/local/orbit-agent/run-agent.sh /usr/local/orbit-agent/check_mk_agent.linux`,
        `curl -fsSo /etc/systemd/system/orbit-agent.service \\`,
        `  ${proto}//${host}/api/agent/systemd`,
      ].join("\n")
    : [
        `mkdir -p /usr/local/orbit-agent`,
        `fetch -o /usr/local/orbit-agent/orbit_agent.py \\`,
        `  ${proto}//${host}/api/agent/script`,
        `fetch -o /usr/local/orbit-agent/run-agent.sh \\`,
        `  ${proto}//${host}/api/agent/run`,
        `chmod 755 /usr/local/orbit-agent/run-agent.sh`,
        `fetch -o /usr/local/etc/rc.d/orbit_agent \\`,
        `  ${proto}//${host}/api/agent/rc`,
        `chmod 755 /usr/local/etc/rc.d/orbit_agent`,
      ].join("\n");
  // printf, not a heredoc: OPNsense/pfSense root shell is tcsh, where heredocs are
  // flaky — and printf works the same in bash, so linux shares it.
  const configCmd = [
    `printf '%s\\n' '${JSON.stringify(cfg)}' > /usr/local/etc/orbit-agent.conf`,
    `chmod 600 /usr/local/etc/orbit-agent.conf`,
  ].join("\n");
  const startCmd = linuxGuide
    ? `systemctl daemon-reload\nsystemctl enable --now orbit-agent`
    : `sysrc orbit_agent_enable=YES\nservice orbit_agent start`;

  const steps = {
    prereq: linuxGuide
      ? `# Needs python3 >= 3.8 and bash (any current Debian/Ubuntu/RHEL); tcpdump enables packet capture.`
      : `# Python 3 ships with OPNsense/pfSense — no pip packages (agent is stdlib-only).`,
    // Download + config + start in one paste (steps 4–6 combined). Blank-line
    // separated, no '#' comments — the tcsh root shell mishandles them interactively.
    install: [downloadCmds, configCmd, startCmd].join("\n\n"),
    logs: linuxGuide ? `journalctl -u orbit-agent -f` : `tail -f /var/log/orbit_agent.log`,
  };

  return (
    <section className="mt-8">
      {/* Section heading */}
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <Radio className="h-4 w-4" />
        Agent Mode
        {agentMode && status && (
          <span
            className={`ml-1 flex items-center gap-1.5 text-xs ${
              connected ? "text-emerald-400" : "text-amber-400"
            }`}
          >
            <span
              className={`inline-block h-1.5 w-1.5 rounded-full ${
                connected ? "bg-emerald-400" : "bg-amber-400"
              }`}
            />
            {connected ? "Connected" : "Not connected"}
          </span>
        )}
      </h2>

      {msg && (
        <div
          className={`mt-2 rounded-lg px-3 py-2 text-sm ${
            msg.ok ? "bg-emerald-900/40 text-emerald-300" : "bg-red-900/40 text-red-300"
          }`}
        >
          {msg.text}
        </div>
      )}

      <div className="mt-3 rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        {!agentMode ? (
          // ----------------------------------------------------------------
          // Polling mode — explain both modes, offer switch
          // ----------------------------------------------------------------
          <>
            <div className="grid gap-3 text-sm sm:grid-cols-2">
              <div className="rounded-lg border border-slate-700 bg-slate-800/60 p-3">
                <p className="font-medium text-slate-300">Polling Mode (active)</p>
                <p className="mt-1 text-slate-500">
                  The dashboard calls the OPNsense REST API every 30 s. The API endpoint must be
                  reachable from the dashboard host.
                </p>
              </div>
              <div className="rounded-lg border border-emerald-800/40 bg-emerald-900/10 p-3">
                <p className="font-medium text-emerald-300">Agent Mode</p>
                <p className="mt-1 text-slate-500">
                  A lightweight daemon on the firewall connects outbound to this dashboard and
                  pushes metrics every 30 s. No inbound port needed — works behind NAT or strict
                  firewall policies.
                </p>
              </div>
            </div>
            <button
              onClick={() => enableMut.mutate()}
              disabled={enableMut.isPending}
              className="mt-4 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              Switch to Agent Mode
            </button>
          </>
        ) : (
          // ----------------------------------------------------------------
          // Agent mode — status bar + collapsible install guide
          // ----------------------------------------------------------------
          <>
            {/* Status bar */}
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-1 text-sm">
                <div className="flex items-center gap-3">
                  <span className="w-20 text-slate-500">Mode</span>
                  <span className="font-medium text-emerald-400">Agent</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="w-20 text-slate-500">Status</span>
                  <span
                    className={`flex items-center gap-1.5 ${
                      connected ? "text-emerald-400" : "text-amber-400"
                    }`}
                  >
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${
                        connected ? "bg-emerald-400" : "bg-amber-400"
                      }`}
                    />
                    {connected ? "Connected" : "Waiting for connection"}
                  </span>
                </div>
                {status?.agent_last_seen && (
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-slate-500">Last seen</span>
                    <span
                      className="text-xs text-slate-400"
                      title={fmtDateTime(status.agent_last_seen)}
                    >
                      {fmtRelative(status.agent_last_seen)}
                    </span>
                  </div>
                )}
                {status?.agent_version && (
                  <div className="flex items-center gap-3">
                    <span className="w-20 text-slate-500">Version</span>
                    <span className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span className="font-mono">{status.agent_version}</span>
                      {status.update_available && status.served_version && (
                        <span className="rounded bg-amber-900/40 px-1.5 py-0.5 text-amber-300">
                          update available → {status.served_version}
                        </span>
                      )}
                    </span>
                  </div>
                )}
                {status?.last_update_error && (
                  <div className="mt-2 rounded-lg border border-red-800/50 bg-red-900/20 px-3 py-2 text-xs text-red-300">
                    <span className="font-medium">Last update rejected</span>
                    {status.last_update_version ? ` (→ ${status.last_update_version})` : ""}:{" "}
                    {status.last_update_error}
                  </div>
                )}
              </div>
              <div className="flex shrink-0 flex-col items-end gap-2">
                {connected && status?.update_available && (
                  <button
                    onClick={() => updateMut.mutate()}
                    disabled={updateMut.isPending}
                    className="rounded-lg border border-amber-700/50 px-3 py-1.5 text-xs text-amber-300 hover:bg-amber-900/20 disabled:opacity-50"
                  >
                    {updateMut.isPending ? "Updating…" : `Update agent → ${status.served_version}`}
                  </button>
                )}
                {connected && (
                  <button
                    onClick={() => refreshMut.mutate()}
                    disabled={refreshMut.isPending}
                    className="rounded-lg border border-emerald-700/50 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-900/20 disabled:opacity-50"
                    title="Force the agent to re-collect logs, firmware and config backup now"
                  >
                    {refreshMut.isPending ? "Refreshing…" : "Refresh now"}
                  </button>
                )}
                {connected && (
                  <button
                    onClick={() => reconnectMut.mutate()}
                    disabled={reconnectMut.isPending}
                    className="rounded-lg border border-sky-700/50 px-3 py-1.5 text-xs text-sky-300 hover:bg-sky-900/20 disabled:opacity-50"
                    title="Drop and re-establish the agent's dashboard WebSocket"
                  >
                    {reconnectMut.isPending ? "Reconnecting…" : "Reconnect"}
                  </button>
                )}
                <button
                  onClick={() => disableMut.mutate()}
                  disabled={disableMut.isPending}
                  className="rounded-lg border border-red-800/50 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/20 disabled:opacity-50"
                >
                  Disable Agent
                </button>
                {!confirmUninstall ? (
                  <button
                    onClick={() => setConfirmUninstall(true)}
                    className="text-xs text-slate-500 hover:text-red-400"
                  >
                    Uninstall agent…
                  </button>
                ) : (
                  <div className="flex flex-col items-end gap-1 rounded-lg border border-red-800/50 bg-red-900/10 p-2 text-xs text-red-300">
                    <span>Remove the agent from the firewall?</span>
                    <span className="text-[11px] text-slate-400">
                      Stops + deletes the agent, its config, and the provisioned relay credentials
                      (and the REST API package on pfSense).
                    </span>
                    <div className="mt-1 flex items-center gap-2">
                      <button
                        onClick={() => uninstallMut.mutate()}
                        disabled={uninstallMut.isPending || !connected}
                        className="rounded bg-red-700/50 px-2 py-0.5 hover:bg-red-700/70 disabled:opacity-50"
                      >
                        {uninstallMut.isPending ? "Removing…" : "Yes, uninstall"}
                      </button>
                      <button
                        onClick={() => setConfirmUninstall(false)}
                        className="text-slate-400 hover:text-slate-200"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Firewall GUI + local API (relay is provisioned internally now).
                Linux servers have neither a web UI nor a local REST API (§25). */}
            {!linuxGuide && (
            <div className="mt-5 rounded-lg border border-slate-700 bg-slate-800/40 p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-300">Firewall GUI</p>
                  <p className="mt-1 text-xs text-slate-500">
                    Reach this firewall through the agent tunnel — no inbound access or VPN needed.{" "}
                    <span className="text-slate-400">Open GUI</span> logs into the web interface on
                    a per-firewall origin; <span className="text-slate-400">Test Local API</span>{" "}
                    probes the firewall&apos;s REST API through the relay.
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    onClick={() => testApiMut.mutate()}
                    disabled={!connected || testApiMut.isPending}
                    className="rounded-lg border border-sky-700/50 px-3 py-1.5 text-xs text-sky-300 hover:bg-sky-900/20 disabled:opacity-50"
                    title={
                      connected
                        ? "Probe the firewall's local API via the agent relay"
                        : "Agent must be connected"
                    }
                  >
                    {testApiMut.isPending ? "Testing…" : "Test Local API"}
                  </button>
                  {status?.gui_proxy_enabled && (
                    <button
                      onClick={() => guiMut.mutate()}
                      disabled={!connected || guiMut.isPending}
                      className="rounded-lg border border-emerald-700/50 px-3 py-1.5 text-xs text-emerald-300 hover:bg-emerald-900/20 disabled:opacity-50"
                      title={connected ? undefined : "Agent must be connected"}
                    >
                      {guiMut.isPending ? "Opening…" : "Open GUI"}
                    </button>
                  )}
                </div>
              </div>
            </div>
            )}

            {/* Guide toggle */}
            <button
              onClick={() => setShowGuide((v) => !v)}
              className="mt-5 flex w-full items-center justify-between rounded-lg border border-slate-700 bg-slate-800/50 px-4 py-2.5 text-sm font-medium text-slate-300 hover:bg-slate-800"
            >
              <span>Installation Guide</span>
              {showGuide ? (
                <ChevronUp className="h-4 w-4 text-slate-500" />
              ) : (
                <ChevronDown className="h-4 w-4 text-slate-500" />
              )}
            </button>

            {showGuide && (
              <div className="mt-5 space-y-6">
                {/* ① Token */}
                <Step number={1} title="Copy your agent token">
                  <p className="text-xs text-slate-500">
                    This token authenticates the agent with this dashboard. It&apos;s already
                    pre-filled into the install command in step 4.
                  </p>
                  <div className="mt-2 flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2">
                    <code className="min-w-0 flex-1 break-all font-mono text-xs text-slate-200">
                      {token ?? <span className="italic text-slate-600">loading…</span>}
                    </code>
                    {token && <CopyButton text={token} />}
                  </div>
                  <div className="mt-2">
                    {!confirmRegen ? (
                      <button
                        onClick={() => setConfirmRegen(true)}
                        className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"
                      >
                        <RefreshCw className="h-3 w-3" />
                        Regenerate token
                      </button>
                    ) : (
                      <span className="flex flex-wrap items-center gap-2 text-xs text-amber-400">
                        This will disconnect the current agent and require a config update on
                        OPNsense.
                        <button
                          onClick={() => enableMut.mutate()}
                          disabled={enableMut.isPending}
                          className="rounded bg-amber-700/40 px-2 py-0.5 hover:bg-amber-700/60 disabled:opacity-50"
                        >
                          Yes, regenerate
                        </button>
                        <button
                          onClick={() => setConfirmRegen(false)}
                          className="text-slate-400 hover:text-slate-200"
                        >
                          Cancel
                        </button>
                      </span>
                    )}
                  </div>
                  <div className="mt-3 border-t border-slate-800 pt-3">
                    <p className="text-xs text-slate-500">
                      Or skip pasting the token: generate a one-time enrollment code. The agent
                      trades it for the token on first start (the config below switches to{" "}
                      <code>enroll_code</code>).
                    </p>
                    {enrollCode ? (
                      <div className="mt-2 flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2">
                        <code className="min-w-0 flex-1 break-all font-mono text-xs text-emerald-300">
                          {enrollCode}
                        </code>
                        <CopyButton text={enrollCode} />
                      </div>
                    ) : (
                      <button
                        onClick={() => enrollMut.mutate()}
                        disabled={enrollMut.isPending}
                        className="mt-2 rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
                      >
                        {enrollMut.isPending ? "Generating…" : "Generate one-time code"}
                      </button>
                    )}
                  </div>
                </Step>

                {/* ② SSH */}
                <Step number={2} title="SSH into the OPNsense shell">
                  <p className="text-xs text-slate-500">
                    On OPNsense: System → Settings → Administration → enable Secure Shell. Then
                    connect from a terminal:
                  </p>
                  <CodeBlock code="ssh root@<opnsense-ip-or-hostname>" />
                </Step>

                {/* ③ Dependencies */}
                <Step number={3} title="Check Python">
                  <p className="text-xs text-slate-500">
                    Python 3 ships with OPNsense/pfSense. The agent is stdlib-only — no pip packages
                    required.
                  </p>
                  <CodeBlock code={steps.prereq} />
                </Step>

                {/* ④ Install + configure + start — one copy-paste */}
                <Step number={4} title="Install, configure & start the agent">
                  <p className="text-xs text-slate-500">
                    One copy-paste does it all: downloads the agent, supervisor and rc.d service
                    from this dashboard (no GitHub access needed), writes the config file (dashboard
                    URL and token pre-filled), then enables and starts the service.
                    {!token && (
                      <span className="ml-1 text-amber-400">
                        Token will appear once agent mode is enabled.
                      </span>
                    )}
                  </p>
                  <CodeBlock code={steps.install} />
                </Step>

                {/* ⑤ Verify */}
                <Step number={5} title="Verify the connection" done={connected}>
                  <div
                    className={`flex items-center gap-2 rounded-lg border px-3 py-2.5 text-sm ${
                      connected
                        ? "border-emerald-800/50 bg-emerald-900/20 text-emerald-300"
                        : "border-slate-700 bg-slate-800/40 text-slate-400"
                    }`}
                  >
                    <span
                      className={`h-2 w-2 shrink-0 rounded-full ${
                        connected ? "bg-emerald-400" : "bg-slate-600"
                      }`}
                    />
                    {connected
                      ? "Agent is connected and pushing metrics."
                      : "Waiting for the agent to connect… (auto-refreshes every 10 s)"}
                  </div>
                  <p className="mt-2 text-xs text-slate-500">
                    To watch live agent logs on OPNsense:
                  </p>
                  <CodeBlock code={steps.logs} />
                </Step>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}
