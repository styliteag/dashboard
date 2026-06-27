import { Settings as SettingsIcon } from "lucide-react";
import CheckmkApiKeys from "../components/settings/CheckmkApiKeys";
import CheckmkExport from "../components/settings/CheckmkExport";

/**
 * Settings hub. Today: Checkmk (API key + export config). Future sections
 * (general .env-backed config, notifications incl. Mattermost/email) slot in as
 * additional cards below.
 */
export default function SettingsPage() {
  return (
    <div className="mx-auto max-w-5xl">
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <SettingsIcon className="h-5 w-5 text-slate-400" /> Settings
      </h1>

      <section className="mt-6">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">Checkmk</h2>
        <p className="mt-1 text-sm text-slate-400">
          Connect Checkmk to the dashboard and choose which service checks are exported. See{" "}
          <code className="rounded bg-slate-800 px-1 py-0.5 text-xs">CHECKMK.md</code> for the full
          integration guide.
        </p>

        <div className="mt-4 space-y-6">
          <CheckmkApiKeys />
          <CheckmkExport />
        </div>
      </section>
    </div>
  );
}
