/**
 * Agent management: enable/disable agent mode, show connection status,
 * display install instructions with token.
 */
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Radio, Copy, Check } from "lucide-react";
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

export default function AgentSection({ instanceId, agentMode }: Props) {
  const queryClient = useQueryClient();
  const [token, setToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const { data: status } = useQuery({
    queryKey: ["agent-status", instanceId],
    queryFn: () => api.get<AgentStatus>(`/api/instances/${instanceId}/agent/status`),
    refetchInterval: 10_000,
    enabled: agentMode,
  });

  const enableMut = useMutation({
    mutationFn: () => api.post<AgentTokenResponse>(`/api/instances/${instanceId}/agent/enable`),
    onSuccess: (data) => {
      setToken(data.agent_token);
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
    },
    onError: (e) => setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Fehler" }),
  });

  const disableMut = useMutation({
    mutationFn: () => api.post(`/api/instances/${instanceId}/agent/disable`),
    onSuccess: () => {
      setToken(null);
      queryClient.invalidateQueries({ queryKey: ["instances"] });
      queryClient.invalidateQueries({ queryKey: ["agent-status", instanceId] });
      setMsg({ ok: true, text: "Agent deaktiviert. Polling-Modus aktiv." });
    },
  });

  const copyToken = async () => {
    if (token) {
      await navigator.clipboard.writeText(token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const dashboardHost = window.location.host;
  const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <Radio className="h-4 w-4" /> Agent
        {agentMode && status && (
          <span className={`ml-2 text-xs ${status.agent_connected ? "text-emerald-400" : "text-red-400"}`}>
            {status.agent_connected ? "verbunden" : "nicht verbunden"}
          </span>
        )}
      </h2>

      {msg && (
        <div className={`mt-2 rounded-lg px-3 py-2 text-sm ${
          msg.ok ? "bg-emerald-900/40 text-emerald-300" : "bg-red-900/40 text-red-300"
        }`}>
          {msg.text}
        </div>
      )}

      <div className="mt-3 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        {!agentMode ? (
          <>
            <p className="text-sm text-slate-400">
              Im <strong>Polling-Modus</strong> fragt das Dashboard die OPNsense-API aktiv ab.
              Im <strong>Agent-Modus</strong> laeuft ein kleiner Agent auf der Firewall und pusht Daten —
              kein eingehender Port noetig.
            </p>
            <button
              onClick={() => enableMut.mutate()}
              disabled={enableMut.isPending}
              className="mt-3 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
            >
              Agent-Modus aktivieren
            </button>
          </>
        ) : (
          <>
            <div className="grid gap-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-500">Modus</span>
                <span className="text-emerald-400">Agent</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Verbunden</span>
                <span className={status?.agent_connected ? "text-emerald-400" : "text-red-400"}>
                  {status?.agent_connected ? "Ja" : "Nein"}
                </span>
              </div>
              {status?.agent_last_seen && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Zuletzt gesehen</span>
                  <span className="text-slate-300">{new Date(status.agent_last_seen).toLocaleString("de-DE")}</span>
                </div>
              )}
            </div>

            {/* Show token after enabling */}
            {token && (
              <div className="mt-4 rounded-lg border border-emerald-800/50 bg-emerald-900/20 p-3">
                <p className="text-xs text-emerald-300 font-semibold">Agent-Token (nur einmalig sichtbar!):</p>
                <div className="mt-1 flex items-center gap-2">
                  <code className="flex-1 break-all rounded bg-slate-800 px-2 py-1 text-xs font-mono text-slate-200">
                    {token}
                  </code>
                  <button onClick={copyToken} className="text-slate-400 hover:text-slate-200">
                    {copied ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                  </button>
                </div>
                <div className="mt-3 text-xs text-slate-400">
                  <p className="font-semibold">Installation auf der OPNsense:</p>
                  <pre className="mt-1 rounded bg-slate-800 p-2 text-slate-300 overflow-x-auto">{
`# 1. Agent installieren
pkg install python311
pip install websockets
# Agent-Script auf die Firewall kopieren

# 2. Config anlegen
cat > /usr/local/etc/opnsense-dash-agent.conf << 'EOF'
{
  "dashboard_url": "${wsProtocol}://${dashboardHost}/api/ws/agent",
  "agent_token": "${token}",
  "push_interval": 30
}
EOF

# 3. Service starten
sysrc opnsense_dash_agent_enable=YES
service opnsense_dash_agent start`
                  }</pre>
                </div>
              </div>
            )}

            <button
              onClick={() => disableMut.mutate()}
              disabled={disableMut.isPending}
              className="mt-4 rounded-lg border border-red-800/50 px-3 py-1.5 text-xs text-red-400 hover:bg-red-900/20"
            >
              Agent deaktivieren (zurueck zu Polling)
            </button>
          </>
        )}
      </div>
    </section>
  );
}
