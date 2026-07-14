import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Ban, KeyRound, LogIn, Users } from "lucide-react";
import { api, apiErrorText } from "../lib/api";
import { fmtDateTime, fmtRelative } from "../lib/datetime";

interface OnlineSession {
  username: string | null;
  user_id: number;
  ip: string | null;
  login_at: string;
  last_seen_at: string;
}

interface PrincipalStat {
  principal: string;
  requests: number;
  last_ip: string | null;
}

interface AccessSummary {
  online: OnlineSession[];
  logins_ok_24h: number;
  logins_failed_24h: number;
  denials_24h: number;
  denials_by_reason_24h: Record<string, number>;
  requests_24h: PrincipalStat[];
}

interface TimelineItem {
  ts: string;
  kind: "auth" | "access" | "denial" | "request";
  label: string;
  result: string | null;
  username: string | null;
  ip: string | null;
  country: string | null;
  instance?: string | null;
  detail: Record<string, unknown> | null;
}

interface TimelinePage {
  items: TimelineItem[];
  next_before: string | null;
}

interface GroupedRow {
  kind: "auth" | "access" | "denial" | "request";
  label: string;
  result: string | null;
  username: string | null;
  ip: string | null;
  country: string | null;
  instance?: string | null;
  count: number;
  last_ts: string;
}

const KIND_FILTERS = [
  { key: "auth", label: "Logins" },
  { key: "denial", label: "Blocked" },
  { key: "access", label: "Access" },
  { key: "request", label: "Requests" },
] as const;

const VIEWS = [
  { key: "detail", label: "Detail" },
  { key: "grouped", label: "Grouped" },
] as const;

type ViewKey = (typeof VIEWS)[number]["key"];

const PAGE_LIMIT = 100;

function kindBadge(item: TimelineItem) {
  if (item.kind === "denial") {
    return <span className="rounded bg-red-950 px-1.5 py-0.5 text-xs text-red-400">blocked</span>;
  }
  if (item.kind === "access") {
    return (
      <span className="rounded bg-sky-950 px-1.5 py-0.5 text-xs text-sky-400">
        {item.label.replace("agent.", "").replace("packet_capture.", "capture.")}
      </span>
    );
  }
  if (item.kind === "auth") {
    const failed = item.result === "error" || item.result === "denied";
    return (
      <span
        className={`rounded px-1.5 py-0.5 text-xs ${
          failed ? "bg-amber-950 text-amber-400" : "bg-emerald-950 text-emerald-400"
        }`}
      >
        {item.label.replace("auth.", "")}
      </span>
    );
  }
  return <span className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">request</span>;
}

function StatCard({
  icon,
  label,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <div className="flex items-center gap-2 text-xs text-slate-500">
        {icon} {label}
      </div>
      <div className="mt-2">{children}</div>
    </div>
  );
}

export default function AccessLogTab() {
  // Requests are polling noise most of the time — off by default, one click away.
  const [kinds, setKinds] = useState<string[]>(["auth", "denial", "access"]);
  const [view, setView] = useState<ViewKey>("detail");
  const [search, setSearch] = useState("");
  const [hoursFilter, setHoursFilter] = useState("");
  const [older, setOlder] = useState<TimelineItem[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadingOlder, setLoadingOlder] = useState(false);

  const kindsParam = kinds.join(",");
  const filterParams = new URLSearchParams({ kinds: kindsParam });
  if (search.trim()) filterParams.set("q", search.trim());
  if (hoursFilter) filterParams.set("hours", hoursFilter);
  const filterQs = filterParams.toString();

  const resetPaging = () => {
    setOlder([]);
    setCursor(null);
  };

  const summary = useQuery({
    queryKey: ["access-summary"],
    queryFn: () => api.get<AccessSummary>("/api/access-log/summary"),
    refetchInterval: 30_000,
  });

  const timeline = useQuery({
    queryKey: ["access-timeline", filterQs],
    queryFn: () =>
      api.get<TimelinePage>(`/api/access-log/timeline?${filterQs}&limit=${PAGE_LIMIT}`),
    refetchInterval: 30_000,
    enabled: view === "detail",
  });

  const grouped = useQuery({
    queryKey: ["access-grouped", filterQs],
    queryFn: () => api.get<GroupedRow[]>(`/api/access-log/grouped?${filterQs}`),
    refetchInterval: 60_000,
    enabled: view === "grouped",
  });

  const toggleKind = (key: string) => {
    setKinds((prev) => {
      const next = prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key];
      return next.length === 0 ? prev : next; // at least one filter stays on
    });
    resetPaging();
  };

  const loadOlder = async () => {
    const before = cursor ?? timeline.data?.next_before;
    if (!before) return;
    setLoadingOlder(true);
    try {
      const page = await api.get<TimelinePage>(
        `/api/access-log/timeline?${filterQs}&limit=${PAGE_LIMIT}&before=${encodeURIComponent(before)}`,
      );
      setOlder((prev) => [...prev, ...page.items]);
      setCursor(page.next_before);
    } finally {
      setLoadingOlder(false);
    }
  };

  const s = summary.data;
  const items = [...(timeline.data?.items ?? []), ...older];
  const hasMore = cursor !== null || Boolean(timeline.data?.next_before);

  return (
    <div>
      {summary.isError && (
        <p className="mt-4 text-sm text-red-400">
          {apiErrorText(summary.error, "Failed to load access summary")}
        </p>
      )}

      {/* Aggregates */}
      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={<Users className="h-4 w-4" />} label="Online now">
          {s && s.online.length === 0 && <p className="text-sm text-slate-500">Nobody online.</p>}
          <ul className="space-y-1">
            {s?.online.map((o) => (
              <li
                key={`${o.user_id}-${o.login_at}`}
                className="flex items-baseline justify-between gap-2 text-sm"
              >
                <span className="text-slate-200">{o.username ?? `user #${o.user_id}`}</span>
                <span
                  className="font-mono text-xs text-slate-500"
                  title={`login ${fmtDateTime(o.login_at)} · last seen ${fmtDateTime(o.last_seen_at)}`}
                >
                  {o.ip ?? "—"}
                </span>
              </li>
            ))}
          </ul>
        </StatCard>

        <StatCard icon={<LogIn className="h-4 w-4" />} label="Logins (24h)">
          <div className="flex items-baseline gap-4">
            <span className="text-2xl font-semibold text-emerald-400">
              {s?.logins_ok_24h ?? "…"}
            </span>
            <span className="text-sm text-slate-500">
              <span className={s && s.logins_failed_24h > 0 ? "text-amber-400" : ""}>
                {s?.logins_failed_24h ?? "…"}
              </span>{" "}
              failed
            </span>
          </div>
        </StatCard>

        <StatCard icon={<Ban className="h-4 w-4" />} label="Blocked (24h)">
          <div className="text-2xl font-semibold text-red-400">{s?.denials_24h ?? "…"}</div>
          <ul className="mt-1 space-y-0.5 text-xs text-slate-500">
            {s &&
              Object.entries(s.denials_by_reason_24h).map(([reason, n]) => (
                <li key={reason}>
                  {reason}: {n}
                </li>
              ))}
          </ul>
        </StatCard>

        <StatCard icon={<KeyRound className="h-4 w-4" />} label="Requests by principal (24h)">
          <ul className="space-y-1 text-sm">
            {s?.requests_24h.slice(0, 6).map((p) => (
              <li key={p.principal} className="flex items-baseline justify-between gap-2">
                <span className="truncate text-slate-200">{p.principal}</span>
                <span className="font-mono text-xs text-slate-500" title={p.last_ip ?? undefined}>
                  {p.requests}
                </span>
              </li>
            ))}
          </ul>
        </StatCard>
      </div>

      {/* Timeline filters */}
      <div className="mt-6 flex flex-wrap items-center gap-2">
        {KIND_FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => toggleKind(f.key)}
            className={`rounded-full border px-3 py-1 text-xs ${
              kinds.includes(f.key)
                ? "border-emerald-700 bg-emerald-950 text-emerald-300"
                : "border-slate-700 bg-slate-900 text-slate-500 hover:text-slate-300"
            }`}
          >
            {f.label}
          </button>
        ))}
        <div className="flex rounded-lg border border-slate-700 text-xs">
          {VIEWS.map((v) => (
            <button
              key={v.key}
              onClick={() => setView(v.key)}
              className={`px-3 py-1 first:rounded-l-lg last:rounded-r-lg ${
                view === v.key
                  ? "bg-slate-700 text-slate-100"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {v.label}
            </button>
          ))}
        </div>
        <input
          type="text"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            resetPaging();
          }}
          placeholder="Search user, IP, action, path…"
          className="w-56 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1 text-xs text-slate-100 placeholder:text-slate-500 focus:border-emerald-600 focus:outline-none"
        />
        <input
          type="number"
          value={hoursFilter}
          onChange={(e) => {
            setHoursFilter(e.target.value);
            resetPaging();
          }}
          placeholder="24"
          min={1}
          title="Only the last N hours"
          className="w-16 rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-100 placeholder:text-slate-500 focus:border-emerald-600 focus:outline-none"
        />
        <span className="text-xs text-slate-600">h</span>
        <span className="ml-auto text-xs text-slate-600">
          Requests are sampled under load; counters above count everything.
        </span>
      </div>

      {/* Grouped view (Logs-page pattern: one row per recurring event) */}
      {view === "grouped" &&
        (grouped.isLoading ? (
          <p className="mt-4 text-slate-500">Loading…</p>
        ) : !grouped.data || grouped.data.length === 0 ? (
          <p className="mt-4 text-slate-500">No events.</p>
        ) : (
          <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-sm">
              <thead className="bg-slate-900 text-left text-xs text-slate-500">
                <tr>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Event</th>
                  <th className="px-3 py-2">User</th>
                  <th className="px-3 py-2">IP</th>
                  <th className="px-3 py-2 text-right">Count</th>
                  <th className="px-3 py-2">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {grouped.data.map((g, i) => (
                  <tr
                    key={`${g.kind}-${g.label}-${g.ip}-${i}`}
                    className="border-t border-slate-800"
                  >
                    <td className="px-3 py-2">
                      {kindBadge({
                        ts: g.last_ts,
                        kind: g.kind,
                        label: g.label,
                        result: g.result,
                        username: g.username,
                        ip: g.ip,
                        country: g.country,
                        detail: null,
                      })}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-300">
                      {g.label}
                      {g.instance ? ` @ ${g.instance}` : ""}
                    </td>
                    <td className="px-3 py-2 text-xs">{g.username ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-500">
                      {g.ip ?? "—"}
                      {g.country ? ` (${g.country})` : ""}
                    </td>
                    <td className="px-3 py-2 text-right text-xs text-slate-400">{g.count}</td>
                    <td
                      className="whitespace-nowrap px-3 py-2 text-xs text-slate-500"
                      title={fmtDateTime(g.last_ts)}
                    >
                      {fmtRelative(g.last_ts)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}

      {/* Timeline */}
      {view === "detail" &&
        (timeline.isLoading ? (
          <p className="mt-4 text-slate-500">Loading…</p>
        ) : items.length === 0 ? (
          <p className="mt-4 text-slate-500">No events.</p>
        ) : (
          <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-sm">
              <thead className="bg-slate-900 text-left text-xs text-slate-500">
                <tr>
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">User</th>
                  <th className="px-3 py-2">IP</th>
                  <th className="px-3 py-2">Detail</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e, i) => (
                  <tr key={`${e.ts}-${e.kind}-${i}`} className="border-t border-slate-800">
                    <td
                      className="whitespace-nowrap px-3 py-2 text-xs text-slate-400"
                      title={fmtDateTime(e.ts)}
                    >
                      {fmtRelative(e.ts)}
                    </td>
                    <td className="px-3 py-2">{kindBadge(e)}</td>
                    <td className="px-3 py-2 text-xs">{e.username ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-500">
                      {e.ip ?? "—"}
                      {e.country ? ` (${e.country})` : ""}
                    </td>
                    <td className="max-w-md truncate px-3 py-2 text-xs text-slate-500">
                      {e.kind === "request"
                        ? `${e.label} → ${e.result}`
                        : e.kind === "denial"
                          ? `${e.label}${e.detail?.path ? ` · ${String(e.detail.path)}` : ""}`
                          : e.kind === "access"
                            ? `${e.instance ?? "—"} · ${e.result ?? ""}`
                            : (e.detail && JSON.stringify(e.detail)) || e.result || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}

      {view === "detail" && hasMore && (
        <div className="mt-3 flex justify-center">
          <button
            onClick={loadOlder}
            disabled={loadingOlder}
            className="rounded-lg border border-slate-700 bg-slate-900 px-4 py-1.5 text-sm text-slate-300 hover:bg-slate-800 disabled:opacity-40"
          >
            {loadingOlder ? "Loading…" : "Load older"}
          </button>
        </div>
      )}
    </div>
  );
}
