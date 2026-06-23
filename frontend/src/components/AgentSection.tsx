/**
 * Agent management: enable/disable + full step-by-step installation guide.
 * Always shows the guide when agent mode is active so any admin can follow
 * the steps without needing to re-enable just to see the instructions.
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Radio, Copy, Check, RefreshCw, ChevronDown, ChevronUp } from "lucide-react";
import { api, ApiError } from "../lib/api";

interface AgentStatus {
  instance_id: number;
  instance_name: string;
  agent_mode: boolean;
  agent_connected: boolean;
  agent_last_seen: string | null;
}

interface AgentTokenResponse {
  instance_id: number;
  agent_token: string;
  agent_mode: boolean;
}

interface Props {
  instanceId: number;
  agentMode: boolean;
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
          done
            ? "bg-emerald-700 text-emerald-100"
            : "bg-slate-800 text-slate-300"
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

export default function AgentSection({ instanceId, agentMode }: Props) {
  const queryClient = useQueryClient();
  const [localToken, setLocalToken] = useState<string | null>(null);
  const [showGuide, setShowGuide] = useState(false);
  const [confirmRegen, setConfirmRegen] = useState(false);
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
    queryFn: () =>
      api.get<{ agent_token: string }>(`/api/instances/${instanceId}/agent/token`),
    enabled: agentMode && localToken === null,
    retry: false,
  });

  const token = localToken ?? tokenData?.agent_token ?? null;
  const connected = status?.agent_connected ?? false;

  const enableMut = useMutation({
    mutationFn: () =>
      api.post<AgentTokenResponse>(`/api/instances/${instanceId}/agent/enable`),
    onSuccess: (data) => {
      setLocalToken(data.agent_token);
      setConfirmRegen(false);
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
      queryClient.invalidateQueries({ queryKey: ["agent-token", instanceId] });
    },
    onError: (e) =>
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Error enabling agent" }),
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

  // Pre-filled config JSON (token + dashboard URL baked in)
  const configJson = JSON.stringify(
    {
      dashboard_url: `${wsProto}://${host}/api/ws/agent`,
      agent_token: token ?? "PASTE_TOKEN_HERE",
      push_interval: 30,
      log_level: "INFO",
    },
    null,
    2,
  );

  const steps = {
    prereq: `# Python 3 ships with OPNsense/pfSense — no pip packages (agent is stdlib-only).`,
    download: [
      `mkdir -p /usr/local/opnsense-dash-agent`,
      `fetch -o /usr/local/opnsense-dash-agent/opnsense_agent.py \\`,
      `  ${proto}//${host}/api/agent/script`,
      `fetch -o /usr/local/opnsense-dash-agent/run-agent.sh \\`,
      `  ${proto}//${host}/api/agent/run`,
      `chmod 755 /usr/local/opnsense-dash-agent/run-agent.sh`,
      `fetch -o /usr/local/etc/rc.d/opnsense_dash_agent \\`,
      `  ${proto}//${host}/api/agent/rc`,
      `chmod 755 /usr/local/etc/rc.d/opnsense_dash_agent`,
    ].join("\n"),
    config: `cat > /usr/local/etc/opnsense-dash-agent.conf << 'EOF'\n${configJson}\nEOF`,
    start: `sysrc opnsense_dash_agent_enable=YES\nservice opnsense_dash_agent start`,
    logs: `tail -f /var/log/opnsense_dash_agent.log`,
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
            msg.ok
              ? "bg-emerald-900/40 text-emerald-300"
              : "bg-red-900/40 text-red-300"
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
                  The dashboard calls the OPNsense REST API every 30 s. The API
                  endpoint must be reachable from the dashboard host.
                </p>
              </div>
              <div className="rounded-lg border border-emerald-800/40 bg-emerald-900/10 p-3">
                <p className="font-medium text-emerald-300">Agent Mode</p>
                <p className="mt-1 text-slate-500">
                  A lightweight daemon on the firewall connects outbound to this
                  dashboard and pushes metrics every 30 s. No inbound port
                  needed — works behind NAT or strict firewall policies.
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
                    <span className="text-xs text-slate-400">
                      {new Date(status.agent_last_seen).toLocaleString()}
                    </span>
                  </div>
                )}
              </div>
              <button
                onClick={() => disableMut.mutate()}
                disabled={disableMut.isPending}
                className="shrink-0 rounded-lg border border-red-800/50 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/20 disabled:opacity-50"
              >
                Disable Agent
              </button>
            </div>

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
                    This token authenticates the agent with this dashboard. You
                    will paste it into the config file in step 5.
                  </p>
                  <div className="mt-2 flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2">
                    <code className="min-w-0 flex-1 break-all font-mono text-xs text-slate-200">
                      {token ?? (
                        <span className="italic text-slate-600">loading…</span>
                      )}
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
                        This will disconnect the current agent and require a
                        config update on OPNsense.
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
                </Step>

                {/* ② SSH */}
                <Step number={2} title="SSH into the OPNsense shell">
                  <p className="text-xs text-slate-500">
                    On OPNsense: System → Settings → Administration → enable
                    Secure Shell. Then connect from a terminal:
                  </p>
                  <CodeBlock code="ssh root@<opnsense-ip-or-hostname>" />
                </Step>

                {/* ③ Dependencies */}
                <Step number={3} title="Check Python">
                  <p className="text-xs text-slate-500">
                    Python 3 ships with OPNsense/pfSense. The agent is
                    stdlib-only — no pip packages required.
                  </p>
                  <CodeBlock code={steps.prereq} />
                </Step>

                {/* ④ Download */}
                <Step number={4} title="Download agent files from this dashboard">
                  <p className="text-xs text-slate-500">
                    Fetch the agent, the supervisor, and the rc.d service file
                    directly from this dashboard — no GitHub access required.
                  </p>
                  <CodeBlock code={steps.download} />
                </Step>

                {/* ⑤ Config */}
                <Step number={5} title="Create the configuration file">
                  <p className="text-xs text-slate-500">
                    The dashboard URL and your token are pre-filled. Copy and
                    run the command as-is.
                    {!token && (
                      <span className="ml-1 text-amber-400">
                        Token will appear once agent mode is enabled.
                      </span>
                    )}
                  </p>
                  <CodeBlock code={steps.config} />
                </Step>

                {/* ⑥ Start */}
                <Step number={6} title="Enable and start the agent service">
                  <CodeBlock code={steps.start} />
                </Step>

                {/* ⑦ Verify */}
                <Step number={7} title="Verify the connection" done={connected}>
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
