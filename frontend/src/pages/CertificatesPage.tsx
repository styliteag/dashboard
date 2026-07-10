import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { BadgeCheck, CheckCircle, AlertTriangle, XCircle, Search, RefreshCw } from "lucide-react";
import { api } from "../lib/api";
import { useAgentModeMap } from "../lib/instances";
import { fmtDate } from "../lib/datetime";
import { EntityCommentBadge } from "../components/CommentBadge";
import { WebUiIconLink } from "../components/WebUiIconLink";
import { useSort, type Accessors } from "../lib/use-sort";
import SortHeader from "../components/SortHeader";
import KpiTile from "../components/KpiTile";
import type { CertEntry, CertOverviewResponse, CertStatus } from "../lib/types";

const CERT_ACCESSORS: Accessors<CertEntry> = {
  status: (c) => c.days_remaining, // urgency-first
  instance: (c) => c.instance_name.toLowerCase(),
  name: (c) => c.name.toLowerCase(),
  issuer: (c) => c.issuer.toLowerCase(),
  expires: (c) => c.not_after,
  remaining: (c) => c.days_remaining,
};

type Filter = "all" | "ok" | "warning" | "critical" | "acme";

/** Status pill for one cert's expiry runway. */
function statusMeta(s: CertStatus): { icon: JSX.Element; cls: string; label: string } {
  if (s === "expired")
    return { icon: <XCircle className="h-4 w-4" />, cls: "text-red-400", label: "Expired" };
  if (s === "critical")
    return { icon: <AlertTriangle className="h-4 w-4" />, cls: "text-red-400", label: "Critical" };
  if (s === "warning")
    return {
      icon: <AlertTriangle className="h-4 w-4" />,
      cls: "text-amber-400",
      label: "Expiring",
    };
  return { icon: <CheckCircle className="h-4 w-4" />, cls: "text-emerald-400", label: "OK" };
}

function remainingLabel(days: number): string {
  if (days < 0) return `expired ${-days}d ago`;
  if (days === 0) return "expires today";
  return `${days}d left`;
}

/**
 * Expiry-runway distribution as a segmented bar — the fleet's certs bucketed by
 * how soon they lapse. Gives the "timeline at a glance" above the detailed,
 * soonest-first table.
 */
function ExpiryTimeline({ certs }: { certs: CertEntry[] }) {
  const buckets = [
    { key: "expired", label: "Expired", cls: "bg-red-600", test: (d: number) => d < 0 },
    { key: "7d", label: "≤ 7 days", cls: "bg-red-500", test: (d: number) => d >= 0 && d < 7 },
    { key: "30d", label: "≤ 30 days", cls: "bg-amber-500", test: (d: number) => d >= 7 && d < 30 },
    { key: "90d", label: "≤ 90 days", cls: "bg-sky-500", test: (d: number) => d >= 30 && d < 90 },
    { key: "90+", label: "> 90 days", cls: "bg-emerald-600", test: (d: number) => d >= 90 },
  ].map((b) => ({ ...b, count: certs.filter((c) => b.test(c.days_remaining)).length }));
  const total = certs.length || 1;

  return (
    <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <p className="mb-2 text-xs font-medium text-slate-400">Expiry runway</p>
      <div className="flex h-3 w-full overflow-hidden rounded-full bg-slate-800">
        {buckets.map((b) =>
          b.count > 0 ? (
            <div
              key={b.key}
              className={b.cls}
              style={{ width: `${(b.count / total) * 100}%` }}
              title={`${b.label}: ${b.count}`}
            />
          ) : null,
        )}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
        {buckets.map((b) => (
          <span key={b.key} className="inline-flex items-center gap-1.5">
            <span className={`h-2 w-2 rounded-sm ${b.cls}`} />
            {b.label} <span className="font-mono text-slate-300">{b.count}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export default function CertificatesPage() {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const agentMode = useAgentModeMap();

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["certs-overview"],
    queryFn: () => api.get<CertOverviewResponse>("/api/certs/overview"),
    refetchInterval: 300_000,
  });

  const all = data?.certs ?? [];
  const filtered = all.filter((c) => {
    const matchSearch =
      !search ||
      c.instance_name.toLowerCase().includes(search.toLowerCase()) ||
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.issuer.toLowerCase().includes(search.toLowerCase());
    const matchFilter =
      filter === "all" ||
      (filter === "ok" && c.status === "ok") ||
      (filter === "warning" && c.status === "warning") ||
      (filter === "critical" && (c.status === "critical" || c.status === "expired")) ||
      (filter === "acme" && c.acme_overdue);
    return matchSearch && matchFilter;
  });

  const { sorted, sort, toggle } = useSort(filtered, CERT_ACCESSORS);

  return (
    <div>
      <h1 className="flex items-center gap-2 text-xl font-semibold">
        <BadgeCheck className="h-5 w-5 text-slate-400" /> Certificates
      </h1>

      {data && (
        <div className="mt-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <KpiTile
            label="Total"
            value={data.total}
            color="text-slate-100"
            onClick={() => setFilter("all")}
          />
          <KpiTile
            label="OK"
            value={data.ok}
            color="text-emerald-400"
            onClick={() => setFilter(filter === "ok" ? "all" : "ok")}
            active={filter === "ok"}
          />
          <KpiTile
            label="Expiring < 30d"
            value={data.warning}
            color="text-amber-400"
            onClick={() => setFilter(filter === "warning" ? "all" : "warning")}
            active={filter === "warning"}
          />
          <KpiTile
            label="Critical / expired"
            value={data.critical + data.expired}
            color="text-red-400"
            onClick={() => setFilter(filter === "critical" ? "all" : "critical")}
            active={filter === "critical"}
          />
          <KpiTile
            label="ACME renewal overdue"
            value={data.acme_overdue}
            color="text-violet-400"
            onClick={() => setFilter(filter === "acme" ? "all" : "acme")}
            active={filter === "acme"}
          />
        </div>
      )}

      {all.length > 0 && <ExpiryTimeline certs={all} />}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search instance, cert, issuer…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 py-2 pl-9 pr-3 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="inline-flex items-center gap-1 rounded-md px-3 py-1.5 text-xs text-slate-400 hover:bg-slate-800 disabled:opacity-40"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {isLoading ? (
        <p className="mt-6 text-slate-500">Loading certificates…</p>
      ) : filtered.length === 0 ? (
        <p className="mt-6 text-slate-500">
          {all.length > 0
            ? "No certificates match the current filter."
            : "No certificates collected yet (agent-mode boxes only)."}
        </p>
      ) : (
        <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full min-w-[900px] text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <SortHeader label="Status" colKey="status" sort={sort} toggle={toggle} />
                <SortHeader label="Instance" colKey="instance" sort={sort} toggle={toggle} />
                <SortHeader label="Certificate" colKey="name" sort={sort} toggle={toggle} />
                <SortHeader label="Issuer" colKey="issuer" sort={sort} toggle={toggle} />
                <SortHeader label="Expires" colKey="expires" sort={sort} toggle={toggle} />
                <SortHeader
                  label="Remaining"
                  colKey="remaining"
                  sort={sort}
                  toggle={toggle}
                  align="right"
                  className="text-right"
                />
              </tr>
            </thead>
            <tbody>
              {sorted.map((c) => {
                const meta = statusMeta(c.status);
                return (
                  <tr
                    key={`${c.instance_id}-${c.refid}`}
                    // group: reveals the row's comment pencil on hover (CommentBadge)
                    className="group border-t border-slate-800 hover:bg-slate-900/50"
                  >
                    <td className="px-3 py-2">
                      <span className={`inline-flex items-center gap-1.5 ${meta.cls}`}>
                        {meta.icon}
                        <span className="text-xs">{meta.label}</span>
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className="inline-flex items-center gap-1.5">
                        <Link
                          to={`/instances/${c.instance_id}`}
                          className="font-medium text-emerald-400 hover:underline"
                        >
                          {c.instance_name}
                        </Link>
                        <WebUiIconLink
                          instanceId={c.instance_id}
                          instanceName={c.instance_name}
                          agentMode={agentMode.get(c.instance_id) ?? false}
                        />
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className="inline-flex flex-wrap items-center gap-1.5">
                        <span className="text-slate-200">{c.name || c.refid}</span>
                        {c.is_gui && (
                          <span className="rounded bg-sky-600/20 px-1.5 py-0.5 text-[10px] font-medium text-sky-300">
                            GUI
                          </span>
                        )}
                        {c.type === "ca" && (
                          <span className="rounded bg-slate-700 px-1.5 py-0.5 text-[10px] font-medium text-slate-300">
                            CA
                          </span>
                        )}
                        <EntityCommentBadge
                          instanceId={c.instance_id}
                          kind="cert"
                          entityKey={c.refid || c.name}
                          scope="all"
                        />
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className="inline-flex flex-wrap items-center gap-1.5">
                        <span className="max-w-[280px] truncate font-mono text-xs text-slate-400">
                          {c.issuer || "—"}
                        </span>
                        {c.acme && (
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                              c.acme_overdue
                                ? "bg-violet-600/30 text-violet-200"
                                : "bg-violet-600/20 text-violet-300"
                            }`}
                            title={
                              c.acme_overdue
                                ? "ACME cert past its auto-renew window — renewal likely failing"
                                : "Issued by an ACME CA (auto-renewing)"
                            }
                          >
                            {c.acme_overdue ? "ACME · renewal overdue" : "ACME"}
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-400">{fmtDate(c.not_after)}</td>
                    <td className={`px-3 py-2 text-right font-mono text-xs ${meta.cls}`}>
                      {remainingLabel(c.days_remaining)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
