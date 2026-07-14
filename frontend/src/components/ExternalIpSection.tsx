import { useQuery } from "@tanstack/react-query";
import { Check, Copy, Globe, Radio, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/api";
import type { ExternalIpInfo } from "../lib/types";
import { fmtRelative } from "../lib/datetime";

/**
 * Top-of-Network-tab block: the box's public IPv4/IPv6 (agent ipify probe), the
 * source IP the hub saw on connect, and a derived "behind NAT" indicator. Renders
 * nothing until at least one address is known (direct-poll instances and agents
 * that haven't reported an address yet stay hidden rather than show blanks).
 */
export default function ExternalIpSection({ instanceId }: { instanceId: number }) {
  const { data } = useQuery({
    queryKey: ["external-ip", instanceId],
    // Public IPs move rarely — the slow (metrics) tier is plenty.
    queryFn: () => api.get<ExternalIpInfo>(`/api/instances/${instanceId}/external-ip`),
    refetchInterval: 60_000,
  });

  if (!data) return null;
  const hasAny = Boolean(data.ipv4 || data.ipv6 || data.source_ip);
  if (!hasAny) return null;

  // Only assert a NAT verdict once there is an IPv4 to reason about (the backend
  // judges NAT on IPv4 only). Otherwise leave the badge off rather than guess.
  const canJudgeNat = Boolean(data.ipv4 || (data.source_ip && data.source_ip.includes(".")));

  return (
    <section className="mb-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <Globe className="h-4 w-4" /> Public IP
        {canJudgeNat && <NatBadge behindNat={data.behind_nat} />}
      </h2>
      <div className="mt-3 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Card icon={<Globe className="h-4 w-4 text-emerald-400" />} label="External IPv4">
          <IpValue value={data.ipv4} />
        </Card>
        <Card icon={<Globe className="h-4 w-4 text-sky-400" />} label="External IPv6">
          <IpValue value={data.ipv6} />
        </Card>
        <Card icon={<Radio className="h-4 w-4 text-indigo-400" />} label="Connects from">
          <IpValue value={data.connected ? data.source_ip : null} />
          {!data.connected && <span className="ml-1 text-xs text-slate-600">(offline)</span>}
        </Card>
      </div>
      {data.checked_at && (
        <p className="mt-2 text-xs text-slate-600" title={data.checked_at}>
          Probed {fmtRelative(data.checked_at)}
        </p>
      )}
    </section>
  );
}

function NatBadge({ behindNat }: { behindNat: boolean }) {
  return behindNat ? (
    <span
      title="The box's public IPv4 is not configured on any of its interfaces — an upstream NAT owns the public address."
      className="inline-flex items-center gap-1 rounded bg-amber-600/20 px-1.5 py-0.5 text-xs text-amber-400"
    >
      <ShieldAlert className="h-3 w-3" /> Behind NAT
    </span>
  ) : (
    <span
      title="The box owns its public IPv4 directly on an interface (no upstream NAT)."
      className="inline-flex items-center gap-1 rounded bg-emerald-600/20 px-1.5 py-0.5 text-xs text-emerald-400"
    >
      <ShieldCheck className="h-3 w-3" /> Direct
    </span>
  );
}

function IpValue({ value }: { value: string | null }) {
  if (!value) return <span className="text-sm text-slate-600">—</span>;
  return (
    <span className="flex items-center gap-1">
      <span className="font-mono text-sm break-all">{value}</span>
      <CopyIcon text={value} />
    </span>
  );
}

function CopyIcon({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handle = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button
      onClick={handle}
      title="Copy to clipboard"
      className="shrink-0 rounded p-1 text-slate-500 transition-colors hover:bg-slate-700 hover:text-slate-200"
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 text-emerald-400" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
    </button>
  );
}

function Card({
  icon,
  label,
  children,
}: {
  icon: React.ReactNode;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-4 py-3">
      <div className="flex items-center gap-2 text-xs text-slate-500">
        {icon} {label}
      </div>
      <div className="mt-1 text-sm">{children}</div>
    </div>
  );
}
