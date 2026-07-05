import { useState, type ReactNode } from "react";
import {
  MessageSquare,
  Send,
  Mail,
  Bot,
  Settings as SettingsIcon,
  BellOff,
  EyeOff,
} from "lucide-react";
import GeneralSettings from "../components/settings/GeneralSettings";
import RestartBackend from "../components/settings/RestartBackend";
import SelectionTree from "../components/settings/SelectionTree";
import CheckmkApiKeys from "../components/settings/CheckmkApiKeys";
import PrometheusApiKeys from "../components/settings/PrometheusApiKeys";
import LlmProviderTests from "../components/settings/LlmProviderTests";
import MuteToggle from "../components/settings/MuteToggle";

// Per-channel temporary-mute setting keys (registry "Maintenance" group).
const MUTE_KEY: Record<string, string> = {
  mattermost: "notify_mattermost_muted",
  telegram: "notify_telegram_muted",
  email: "notify_email_muted",
};

/**
 * Settings hub, split into tabs to keep each section short:
 *  - General: runtime-overridable .env defaults (polling, retention, …).
 *  - One tab per notification channel (Mattermost / Telegram / Email): its
 *    connection config + which alert categories it receives.
 *  - Checkmk: API key + export config (selection, aggregate, blackout).
 *  - Prometheus: dedicated read-only API key creation for /api/export/prometheus.
 */
const TABS = [
  { key: "general", label: "General" },
  { key: "mattermost", label: "Mattermost" },
  { key: "telegram", label: "Telegram" },
  { key: "email", label: "Email" },
  { key: "ai", label: "AI" },
  { key: "checkmk", label: "Checkmk" },
  { key: "prometheus", label: "Prometheus" },
] as const;
type Tab = (typeof TABS)[number]["key"];

// (settings group, channel key, tab icon, intro) for the three channel tabs.
const CHANNELS: Record<
  string,
  { group: string; channel: string; icon: ReactNode; intro: ReactNode }
> = {
  mattermost: {
    group: "Mattermost",
    channel: "mattermost",
    icon: <MessageSquare className="h-4 w-4 text-slate-400" />,
    intro: <>Post alerts to a Mattermost channel via an incoming webhook.</>,
  },
  telegram: {
    group: "Telegram",
    channel: "telegram",
    icon: <Send className="h-4 w-4 text-slate-400" />,
    intro: <>Send alerts through a Telegram bot to a chat or channel.</>,
  },
  email: {
    group: "Email",
    channel: "email",
    icon: <Mail className="h-4 w-4 text-slate-400" />,
    intro: <>Email alerts over SMTP. Secrets (SMTP password) are stored encrypted.</>,
  },
};

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>(
    () => (localStorage.getItem("settings.tab") as Tab) || "general",
  );
  const selectTab = (t: Tab) => {
    localStorage.setItem("settings.tab", t);
    setTab(t);
  };

  const channel = CHANNELS[tab];

  return (
    <div className="mx-auto max-w-5xl">
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <SettingsIcon className="h-5 w-5 text-slate-400" /> Settings
      </h1>

      <div className="mt-5 flex flex-wrap gap-1 border-b border-slate-800">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => selectTab(t.key)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm transition-colors ${
              tab === t.key
                ? "border-emerald-500 text-slate-100"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "general" && (
        <section className="mt-6 space-y-6">
          {/* "Maintenance" excluded: its bool toggles render as switches on their own
              tabs (MuteToggle), not as text fields in the generic settings list.
              "Checkmk" excluded: rendered on the Checkmk tab next to the export config. */}
          <GeneralSettings
            exclude={["Mattermost", "Telegram", "Email", "LLM", "Maintenance", "Checkmk"]}
          />
          <RestartBackend />
        </section>
      )}

      {tab === "ai" && (
        <section className="mt-6 space-y-6">
          <GeneralSettings
            include={["LLM"]}
            title="LLM providers"
            icon={<Bot className="h-4 w-4 text-slate-400" />}
            intro={
              <>
                API keys for AI log analysis. Keys are stored encrypted; only the chosen provider is
                contacted, and log data is anonymized before it is sent.
              </>
            }
          />
          <LlmProviderTests />
        </section>
      )}

      {channel && (
        <section className="mt-6 space-y-6">
          <MuteToggle
            settingKey={MUTE_KEY[channel.channel]}
            icon={BellOff}
            title={`Temporarily mute ${channel.group} alerts`}
            idleNote={`${channel.group} alerts are delivered normally.`}
            activeNote={`${channel.group} alerts are paused — real alerts are not sent.`}
            activeBadge={`Muted — no ${channel.group} alerts sent`}
            hint="Manual toggle — stays until you switch it back. An explicit “Send test” below still fires."
          />
          <GeneralSettings
            include={[channel.group]}
            title={`${channel.group} connection`}
            icon={channel.icon}
            intro={channel.intro}
          />
          <SelectionTree consumer={channel.channel} />
        </section>
      )}

      {tab === "checkmk" && (
        <section className="mt-6">
          <p className="text-sm text-slate-400">
            Connect Checkmk to the dashboard and choose which service checks are exported. See{" "}
            <code className="rounded bg-slate-800 px-1 py-0.5 text-xs">CHECKMK.md</code> for the
            full integration guide.
          </p>
          <div className="mt-4 space-y-6">
            <MuteToggle
              settingKey="checkmk_blackout"
              icon={EyeOff}
              title="Checkmk blackout"
              idleNote="The Checkmk export includes all instances and their checks."
              activeNote="The Checkmk export is empty — Checkmk sees every service as stale/gone."
              activeBadge="Blackout — export empty"
              hint="Manual toggle — stays until you switch it back. Use during maintenance to silence Checkmk."
            />
            <GeneralSettings
              include={["Checkmk"]}
              title="Checkmk export"
              intro={
                <>
                  Collapse high-fan-out checks (certificates, IPsec tunnels, services…) into one
                  aggregate service per category. Changing this alters which services Checkmk
                  discovers — re-inventorize the hosts afterwards.
                </>
              }
            />
            <CheckmkApiKeys />
            <SelectionTree consumer="checkmk" />
          </div>
        </section>
      )}

      {tab === "prometheus" && (
        <section className="mt-6">
          <p className="text-sm text-slate-400">
            Scrape{" "}
            <code className="rounded bg-slate-800 px-1 py-0.5 text-xs">/api/export/prometheus</code>{" "}
            for Grafana / Prometheus. Returns all checks (no selection rules; filter in PromQL). Use
            a read-only API key below. See README.md for the endpoint details.
          </p>
          <div className="mt-4">
            <PrometheusApiKeys />
          </div>
        </section>
      )}
    </div>
  );
}
