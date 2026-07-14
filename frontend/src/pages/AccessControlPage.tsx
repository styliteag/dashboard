import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Download, Globe2, Plus, ShieldAlert, X } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import { fmtRelative } from "../lib/datetime";
import { useAuth } from "../lib/use-auth";

interface GeoipSettings {
  enabled: boolean;
  countries: string[];
  whitelist: string[];
  updated_at?: string | null;
  updated_by?: string | null;
}

interface GeoipSaveResult {
  saved: boolean;
  self_blocked: boolean;
  self_ip: string;
  self_country: string | null;
  settings: GeoipSettings;
}

interface GeoipDenials {
  since: string | null;
  total: number;
  by_reason: Record<string, number>;
  top_countries: { country: string; count: number }[];
  fail_open_allows: number;
  recent: {
    at: string;
    ip: string;
    country: string | null;
    path: string;
    reason: string;
  }[];
}

interface GeoipStatus {
  kill_switch_active: boolean;
  enforcing: boolean;
  db: {
    path: string;
    present: boolean;
    readable: boolean;
    size_bytes: number;
    modified_unix: number | null;
  };
  last_download: { at: string | null; ok: boolean | null; detail: string };
  dyndns: { hostname: string; ips: string[]; resolved_at: string | null; error: string | null }[];
  credentials_set: boolean;
  crowdsec: {
    disabled: boolean;
    key_set: boolean;
    configured: boolean;
    banned_count: number;
    at: string | null;
    ok: boolean | null;
    detail: string;
  };
}

// Common ISO-3166-1 alpha-2 suggestions for an MSP fleet in DACH/EU — any
// valid two-letter code can be typed freely.
const COUNTRY_SUGGESTIONS = [
  "DE",
  "AT",
  "CH",
  "NL",
  "BE",
  "LU",
  "FR",
  "IT",
  "PL",
  "CZ",
  "DK",
  "ES",
  "PT",
  "GB",
  "IE",
  "SE",
  "NO",
  "FI",
  "US",
];

function ChipInput({
  values,
  onChange,
  placeholder,
  validate,
  normalize,
}: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder: string;
  validate?: (v: string) => string | null;
  normalize?: (v: string) => string;
}) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  const add = (raw: string) => {
    const value = (normalize ? normalize(raw) : raw).trim();
    if (!value) return;
    const problem = validate ? validate(value) : null;
    if (problem) {
      setError(problem);
      return;
    }
    setError(null);
    if (!values.includes(value)) onChange([...values, value]);
    setDraft("");
  };

  return (
    <div>
      <div className="flex flex-wrap items-center gap-1.5 rounded border border-slate-700 bg-slate-900 px-2 py-1.5">
        {values.map((v) => (
          <span
            key={v}
            className="flex items-center gap-1 rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-200"
          >
            {v}
            <button
              type="button"
              className="text-slate-500 hover:text-red-400"
              onClick={() => onChange(values.filter((x) => x !== v))}
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
        <input
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === ",") {
              e.preventDefault();
              add(draft);
            }
          }}
          onBlur={() => draft && add(draft)}
          placeholder={placeholder}
          className="min-w-[10rem] flex-1 bg-transparent text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none"
        />
        <button
          type="button"
          onClick={() => add(draft)}
          className="text-slate-500 hover:text-emerald-400"
        >
          <Plus className="h-4 w-4" />
        </button>
      </div>
      {error && <p className="mt-1 text-xs text-red-400">{error}</p>}
    </div>
  );
}

export default function AccessControlPage() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [enabled, setEnabled] = useState(false);
  const [countries, setCountries] = useState<string[]>([]);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [dirty, setDirty] = useState(false);
  const [confirmSelfBlock, setConfirmSelfBlock] = useState<GeoipSaveResult | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const settingsQuery = useQuery({
    queryKey: ["geoip-settings"],
    queryFn: () => api.get<GeoipSettings>("/api/geoip/settings"),
    enabled: !!user?.is_superadmin,
  });
  const statusQuery = useQuery({
    queryKey: ["geoip-status"],
    queryFn: () => api.get<GeoipStatus>("/api/geoip/status"),
    enabled: !!user?.is_superadmin,
    refetchInterval: 30_000,
  });
  const denialsQuery = useQuery({
    queryKey: ["geoip-denials"],
    queryFn: () => api.get<GeoipDenials>("/api/geoip/denials"),
    enabled: !!user?.is_superadmin,
    refetchInterval: 30_000,
  });

  useEffect(() => {
    if (settingsQuery.data && !dirty) {
      setEnabled(settingsQuery.data.enabled);
      setCountries(settingsQuery.data.countries);
      setWhitelist(settingsQuery.data.whitelist);
    }
  }, [settingsQuery.data, dirty]);

  const save = useMutation({
    mutationFn: (dryRun: boolean) =>
      api.put<GeoipSaveResult>(`/api/geoip/settings?dry_run=${dryRun}`, {
        enabled,
        countries,
        whitelist,
      }),
    onError: (e) => setError(apiErrorText(e, "saving failed")),
  });

  const refreshDb = useMutation({
    mutationFn: () => api.post<{ ok: boolean | null; detail: string }>("/api/geoip/db/refresh"),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["geoip-status"] }),
  });

  const doSave = async () => {
    setError(null);
    setMessage(null);
    // Dry-run first: warn (not block, DR-G5) when the new rules would lock the
    // saving superadmin out of their own session.
    const preview = await save.mutateAsync(true);
    if (preview.self_blocked) {
      setConfirmSelfBlock(preview);
      return;
    }
    await commit();
  };

  const commit = async () => {
    setConfirmSelfBlock(null);
    const result = await save.mutateAsync(false);
    setDirty(false);
    setMessage(
      result.self_blocked
        ? "Saved — WARNING: your current IP would now be blocked. Keep this session open and fix the config, or use DASH_GEOIP_DISABLE."
        : "Saved.",
    );
    queryClient.invalidateQueries({ queryKey: ["geoip-settings"] });
    queryClient.invalidateQueries({ queryKey: ["geoip-status"] });
  };

  if (!user?.is_superadmin) {
    return <p className="text-sm text-slate-400">Superadmin only.</p>;
  }

  const status = statusQuery.data;
  const dbAgeDays =
    status?.db.modified_unix != null
      ? Math.floor((Date.now() / 1000 - status.db.modified_unix) / 86400)
      : null;

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="flex items-center gap-2 text-lg font-semibold text-slate-100">
        <Globe2 className="h-5 w-5 text-emerald-400" /> Access Control (GeoIP)
      </h1>
      <p className="mt-1 text-sm text-slate-400">
        Restrict dashboard access by country. Agents and API keys are never blocked. Empty
        configuration allows everyone.
      </p>

      {status?.kill_switch_active && (
        <div className="mt-4 flex items-center gap-2 rounded border border-amber-700 bg-amber-950/40 px-3 py-2 text-sm text-amber-300">
          <ShieldAlert className="h-4 w-4 shrink-0" />
          Kill switch DASH_GEOIP_DISABLE is active — GeoIP enforcement is OFF regardless of the
          settings below.
        </div>
      )}
      {status && !status.db.readable && (
        <div className="mt-4 flex items-center gap-2 rounded border border-red-800 bg-red-950/40 px-3 py-2 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          GeoIP database missing/unreadable at {status.db.path} — country checks FAIL OPEN until
          fixed.
        </div>
      )}

      <section className="mt-6 space-y-4 rounded border border-slate-800 bg-slate-900/60 p-4">
        <label className="flex items-center gap-2 text-sm text-slate-200">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => {
              setEnabled(e.target.checked);
              setDirty(true);
            }}
            className="h-4 w-4 accent-emerald-500"
          />
          Enable GeoIP restriction
        </label>

        <div>
          <p className="mb-1 text-sm text-slate-300">Allowed countries (ISO codes)</p>
          <ChipInput
            values={countries}
            onChange={(next) => {
              setCountries(next);
              setDirty(true);
            }}
            placeholder="DE, AT, CH …"
            normalize={(v) => v.toUpperCase()}
            validate={(v) => (/^[A-Z]{2}$/.test(v) ? null : "two-letter ISO code expected")}
          />
          <p className="mt-1 text-xs text-slate-500">
            Suggestions:{" "}
            {COUNTRY_SUGGESTIONS.filter((c) => !countries.includes(c))
              .slice(0, 10)
              .map((c) => (
                <button
                  key={c}
                  type="button"
                  className="mr-1 text-slate-400 underline decoration-dotted hover:text-emerald-400"
                  onClick={() => {
                    setCountries([...countries, c]);
                    setDirty(true);
                  }}
                >
                  {c}
                </button>
              ))}
          </p>
        </div>

        <div>
          <p className="mb-1 text-sm text-slate-300">
            Whitelist (always allowed): CIDR/IP or DynDNS hostname
          </p>
          <ChipInput
            values={whitelist}
            onChange={(next) => {
              setWhitelist(next);
              setDirty(true);
            }}
            placeholder="10.0.0.0/8, 2001:db8::/32, host.dyndns.de …"
          />
          <p className="mt-1 text-xs text-slate-500">
            With countries configured, private LAN/VPN addresses have no country and get blocked —
            whitelist your internal networks here. DynDNS names are re-resolved every 5 minutes
            (IPv4 + IPv6).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={doSave}
            disabled={save.isPending || !dirty}
            className="rounded bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
          >
            Save
          </button>
          {message && <span className="text-xs text-emerald-400">{message}</span>}
          {error && <span className="text-xs text-red-400">{error}</span>}
        </div>
      </section>

      {confirmSelfBlock && (
        <div className="mt-4 rounded border border-amber-700 bg-amber-950/40 p-4 text-sm text-amber-200">
          <p className="flex items-center gap-2 font-medium">
            <AlertTriangle className="h-4 w-4" /> This would lock YOU out
          </p>
          <p className="mt-2">
            Your current IP {confirmSelfBlock.self_ip}
            {confirmSelfBlock.self_country
              ? ` (${confirmSelfBlock.self_country})`
              : " (no country — private address?)"}{" "}
            would be blocked by these rules. Add your network to the whitelist, or save anyway if
            this is intentional (rescue: DASH_GEOIP_DISABLE=true + restart).
          </p>
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              onClick={commit}
              className="rounded bg-amber-600 px-3 py-1 text-xs font-medium text-white hover:bg-amber-500"
            >
              Save anyway
            </button>
            <button
              type="button"
              onClick={() => setConfirmSelfBlock(null)}
              className="rounded bg-slate-700 px-3 py-1 text-xs text-slate-200 hover:bg-slate-600"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <section className="mt-6 rounded border border-slate-800 bg-slate-900/60 p-4 text-sm">
        <h2 className="font-medium text-slate-200">GeoIP database</h2>
        <div className="mt-2 space-y-1 text-xs text-slate-400">
          <p>
            Status:{" "}
            {status?.db.readable ? (
              <span className="text-emerald-400">
                loaded ({Math.round((status.db.size_bytes / 1024 / 1024) * 10) / 10} MB
                {dbAgeDays != null ? `, ${dbAgeDays} d old` : ""})
              </span>
            ) : (
              <span className="text-red-400">not available</span>
            )}
          </p>
          <p>
            Last download: {status?.last_download.at ? fmtRelative(status.last_download.at) : "—"} —{" "}
            {status?.last_download.detail}
          </p>
          {!status?.credentials_set && (
            <p className="text-amber-400">
              No MaxMind credentials configured (DASH_MAXMIND_ACCOUNT_ID / _LICENSE_KEY) — weekly
              auto-update is idle.
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={() => refreshDb.mutate()}
          disabled={refreshDb.isPending || !status?.credentials_set}
          className="mt-3 flex items-center gap-1.5 rounded bg-slate-700 px-3 py-1.5 text-xs text-slate-200 hover:bg-slate-600 disabled:opacity-50"
        >
          <Download className="h-3.5 w-3.5" />
          {refreshDb.isPending ? "Downloading…" : "Download now"}
        </button>

        <div className="mt-4 border-t border-slate-800 pt-3">
          <h3 className="text-xs font-medium text-slate-300">CrowdSec blocklist</h3>
          {status?.crowdsec.configured ? (
            <p className="mt-1 text-xs text-slate-400">
              {status.crowdsec.ok === false ? (
                <span className="text-amber-400" title={status.crowdsec.detail}>
                  sync failing — last known bans stay active
                </span>
              ) : (
                <span className="text-emerald-400">
                  active, {status.crowdsec.banned_count} banned
                </span>
              )}
              {status.crowdsec.at && (
                <span className="ml-1 text-slate-500">
                  (synced {fmtRelative(status.crowdsec.at)})
                </span>
              )}
            </p>
          ) : status?.crowdsec.disabled ? (
            <p className="mt-1 text-xs text-amber-400">
              Switched off via DASH_CROWDSEC_DISABLE=true
              {status.crowdsec.key_set ? " (API key stays configured)" : ""}.
            </p>
          ) : (
            <p className="mt-1 text-xs text-slate-500">
              Not configured — set DASH_CROWDSEC_API_KEY (bouncer key from the CrowdSec sidecar) to
              activate. Bans then deny listed IPs on every request; the whitelist above always wins.
            </p>
          )}
        </div>

        <div className="mt-4 border-t border-slate-800 pt-3">
          <h3 className="text-xs font-medium text-slate-300">Denied requests</h3>
          {denialsQuery.data && denialsQuery.data.total > 0 ? (
            <div className="mt-1 space-y-2 text-xs">
              <p className="text-slate-400">
                <span className="font-medium text-red-400">{denialsQuery.data.total} denied</span>
                {denialsQuery.data.since && (
                  <span className="text-slate-500">
                    {" "}
                    since {fmtRelative(denialsQuery.data.since)} (persisted; totals count
                    everything, the list below is sampled under floods)
                  </span>
                )}
                {denialsQuery.data.fail_open_allows > 0 && (
                  <span className="ml-2 text-amber-400">
                    {denialsQuery.data.fail_open_allows} allowed with missing DB (fail-open)
                  </span>
                )}
              </p>
              <p className="text-slate-400">
                {Object.entries(denialsQuery.data.by_reason).map(([reason, count]) => (
                  <span
                    key={reason}
                    className="mr-1.5 rounded bg-slate-800 px-1.5 py-0.5 text-slate-300"
                  >
                    {reason}: {count}
                  </span>
                ))}
                {denialsQuery.data.top_countries.slice(0, 8).map((c) => (
                  <span
                    key={c.country}
                    className="mr-1.5 rounded bg-slate-800 px-1.5 py-0.5 text-slate-400"
                  >
                    {c.country} ×{c.count}
                  </span>
                ))}
              </p>
              <table className="w-full text-xs">
                <thead className="text-left text-slate-600">
                  <tr>
                    <th className="py-0.5 font-normal">When</th>
                    <th className="py-0.5 font-normal">IP</th>
                    <th className="py-0.5 font-normal">Country</th>
                    <th className="py-0.5 font-normal">Path</th>
                    <th className="py-0.5 font-normal">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {denialsQuery.data.recent.slice(0, 15).map((d, i) => (
                    <tr key={`${d.at}-${d.ip}-${i}`} className="border-t border-slate-800/60">
                      <td className="py-0.5 text-slate-500">{fmtRelative(d.at)}</td>
                      <td className="py-0.5 text-slate-300">{d.ip}</td>
                      <td className="py-0.5 text-slate-400">{d.country ?? "—"}</td>
                      <td className="max-w-[14rem] truncate py-0.5 text-slate-500">{d.path}</td>
                      <td className="py-0.5 text-slate-400">{d.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="mt-1 text-xs text-slate-500">No denied requests since backend start.</p>
          )}
        </div>

        {status && status.dyndns.length > 0 && (
          <div className="mt-4">
            <h3 className="text-xs font-medium text-slate-300">DynDNS whitelist entries</h3>
            <table className="mt-1 w-full text-xs">
              <tbody>
                {status.dyndns.map((h) => (
                  <tr key={h.hostname} className="border-t border-slate-800">
                    <td className="py-1 text-slate-300">{h.hostname}</td>
                    <td className="py-1 text-slate-400">{h.ips.join(", ") || "—"}</td>
                    <td className="py-1 text-slate-500">
                      {h.error ? (
                        <span className="text-amber-400" title={h.error}>
                          stale ({h.resolved_at ? fmtRelative(h.resolved_at) : "never resolved"})
                        </span>
                      ) : h.resolved_at ? (
                        fmtRelative(h.resolved_at)
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
