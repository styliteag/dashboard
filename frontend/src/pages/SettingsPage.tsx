import { useState, type ReactNode } from "react";
import { MessageSquare, Send, Mail, Settings as SettingsIcon } from "lucide-react";
import GeneralSettings from "../components/settings/GeneralSettings";
import ChannelAlertSelection from "../components/settings/ChannelAlertSelection";
import CheckmkApiKeys from "../components/settings/CheckmkApiKeys";
import CheckmkExport from "../components/settings/CheckmkExport";

/**
 * Settings hub, split into tabs to keep each section short:
 *  - General: runtime-overridable .env defaults (polling, retention, …).
 *  - One tab per notification channel (Mattermost / Telegram / Email): its
 *    connection config + which alert categories it receives.
 *  - Checkmk: API key + export config.
 */
const TABS = [
  { key: "general", label: "General" },
  { key: "mattermost", label: "Mattermost" },
  { key: "telegram", label: "Telegram" },
  { key: "email", label: "Email" },
  { key: "checkmk", label: "Checkmk" },
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
        <section className="mt-6">
          <GeneralSettings exclude={["Mattermost", "Telegram", "Email"]} />
        </section>
      )}

      {channel && (
        <section className="mt-6 space-y-6">
          <GeneralSettings
            include={[channel.group]}
            title={`${channel.group} connection`}
            icon={channel.icon}
            intro={channel.intro}
          />
          <ChannelAlertSelection channel={channel.channel} />
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
            <CheckmkApiKeys />
            <CheckmkExport />
          </div>
        </section>
      )}
    </div>
  );
}
