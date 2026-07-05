import { useQuery } from "@tanstack/react-query";
import { ArrowLeftRight } from "lucide-react";
import { api } from "../lib/api";
import { fmtBytes, fmtDuration } from "../lib/format";
import { fmtDateTime, fmtRelative } from "../lib/datetime";

interface PfTopTalker {
  ip: string;
  states: number;
  bytes: number;
}

interface PfTopInterface {
  name: string;
  states: number;
  bytes: number;
}

interface PfTopProtocol {
  proto: string;
  states: number;
  bytes: number;
}

interface PfTopFlow {
  src: string;
  sport: string;
  dst: string;
  dport: string;
  proto: string;
  iface: string;
  state: string;
  bytes: number;
  pkts: number;
  age_s: number;
}

interface PfTopSummary {
  ts: string;
  total_states: number;
  top_sources: PfTopTalker[];
  top_dests: PfTopTalker[];
  interfaces: PfTopInterface[];
  protocols: PfTopProtocol[];
  top_flows: PfTopFlow[];
}

function host(ip: string, port: string): string {
  if (!port) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

function TalkerTable({ title, rows }: { title: string; rows: PfTopTalker[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="w-full text-sm">
        <thead className="bg-slate-900 text-left text-xs text-slate-500">
          <tr>
            <th className="px-3 py-2">{title}</th>
            <th className="px-3 py-2 text-right">States</th>
            <th className="px-3 py-2 text-right">Bytes</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.ip} className="border-t border-slate-800">
              <td className="px-3 py-2 font-mono text-xs">{t.ip}</td>
              <td className="px-3 py-2 text-right">{t.states}</td>
              <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(t.bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * pf state-table insight (agent push, ~5-min cadence): top source/dest talkers by
 * state-lifetime bytes, states per interface/protocol and the biggest flows.
 * Renders nothing until the first agent push (direct/Securepoint instances never
 * have this data). "Bytes" are totals over each state's lifetime, not rates.
 */
export default function TopTalkersSection({ instanceId }: { instanceId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ["pf-top", instanceId],
    queryFn: () => api.get<PfTopSummary | null>(`/api/instances/${instanceId}/pf-top`),
    refetchInterval: 60_000,
  });

  if (isLoading || !data || data.total_states === 0) return null;

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <ArrowLeftRight className="h-4 w-4" /> Top Talkers
        <span className="font-normal text-slate-500">
          · {data.total_states} states ·{" "}
          <span title={fmtDateTime(data.ts)}>{fmtRelative(data.ts)}</span>
        </span>
      </h2>

      <div className="mt-3 grid gap-4 lg:grid-cols-2">
        <TalkerTable title="Source" rows={data.top_sources} />
        <TalkerTable title="Destination" rows={data.top_dests} />
      </div>

      <div className="mt-4 flex flex-wrap gap-2 text-xs">
        {data.interfaces.map((i) => (
          <span
            key={i.name}
            className="rounded-full border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-400"
            title={fmtBytes(i.bytes)}
          >
            {i.name}: {i.states} states
          </span>
        ))}
        {data.protocols.map((p) => (
          <span
            key={p.proto}
            className="rounded-full border border-slate-800 bg-slate-900 px-2.5 py-1 text-slate-500"
            title={fmtBytes(p.bytes)}
          >
            {p.proto}: {p.states}
          </span>
        ))}
      </div>

      {data.top_flows.length > 0 && (
        <div className="mt-4 overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs text-slate-500">
              <tr>
                <th className="px-3 py-2">Source</th>
                <th className="px-3 py-2">Destination</th>
                <th className="px-3 py-2">Proto</th>
                <th className="px-3 py-2">Interface</th>
                <th className="px-3 py-2 text-right">Bytes</th>
                <th className="px-3 py-2 text-right">Pakete</th>
                <th className="px-3 py-2 text-right">Alter</th>
              </tr>
            </thead>
            <tbody>
              {data.top_flows.map((f, idx) => (
                <tr key={idx} className="border-t border-slate-800">
                  <td className="px-3 py-2 font-mono text-xs">{host(f.src, f.sport)}</td>
                  <td className="px-3 py-2 font-mono text-xs">{host(f.dst, f.dport)}</td>
                  <td className="px-3 py-2 text-slate-400">{f.proto}</td>
                  <td className="px-3 py-2 text-slate-400">{f.iface}</td>
                  <td className="px-3 py-2 text-right font-mono text-xs">{fmtBytes(f.bytes)}</td>
                  <td className="px-3 py-2 text-right font-mono text-xs">
                    {f.pkts.toLocaleString("de-DE")}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-xs">{fmtDuration(f.age_s)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
