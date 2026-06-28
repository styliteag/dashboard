import { useState } from "react";
import { Bell, Settings as SettingsIcon } from "lucide-react";
import GeneralSettings from "../components/settings/GeneralSettings";
import CheckmkApiKeys from "../components/settings/CheckmkApiKeys";
import CheckmkExport from "../components/settings/CheckmkExport";

/**
 * Settings hub, split into tabs to keep each section short:
 *  - General: runtime-overridable .env defaults (polling, retention, …).
 *  - Notifications: alert channels (Mattermost, email, + the test button).
 *  - Checkmk: API key + export config.
 * New notification channels and future Mattermost options slot into their tabs.
 */
const TABS = [
  { key: "general", label: "General" },
  { key: "notifications", label: "Notifications" },
  { key: "checkmk", label: "Checkmk" },
] as const;
type Tab = (typeof TABS)[number]["key"];

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>(
    () => (localStorage.getItem("settings.tab") as Tab) || "general",
  );
  const selectTab = (t: Tab) => {
    localStorage.setItem("settings.tab", t);
    setTab(t);
  };

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
          <GeneralSettings exclude={["Notifications"]} />
        </section>
      )}

      {tab === "notifications" && (
        <section className="mt-6">
          <GeneralSettings
            include={["Notifications"]}
            title="Notification channels"
            icon={<Bell className="h-4 w-4 text-slate-400" />}
            intro={
              <>
                Where instance up/down and service-check alerts are delivered. Secrets (webhook
                tokens, SMTP password) are stored encrypted. Use “Send test” to verify each channel.
              </>
            }
          />
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
