import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { Network } from "lucide-react";
import { api } from "../lib/api";

interface Iface {
  name: string;
  status: string;
  address: string | null;
  bytes_received: number;
  bytes_transmitted: number;
  in_errors: number;
  out_errors: number;
  collisions: number;
  rx_rate: number;
  tx_rate: number;
}

interface SystemStatus {
  interfaces: Iface[];
}

// Pseudo/virtual interfaces report Oerrs from BUM-flood/ENOBUFS, not wire faults
// (see _IFACE_SKIP_PREFIXES in backend/src/app/checks/evaluate.py). The health
// check ignores them — mirror that here so their counters render neutral, not as
// an amber alarm.
const ERR_SKIP_PREFIXES = [
  "lo",
  "enc",
  "pflog",
  "pfsync",
  "gif",
  "stf",
  "bridge",
  "lagg",
  "gre",
  "ovpn",
  "tun",
  "tap",
  "wg",
];

const isErrSkipped = (name: string): boolean =>
  ERR_SKIP_PREFIXES.some((p) => name.startsWith(p));

function fmtRate(bps: number | null): string {
  if (bps === null) return "…";
  if (bps < 1) return "0";
  const units = ["B/s", "KB/s", "MB/s", "GB/s"];
  let v = bps;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export default function InterfacesSection({ instanceId }: { instanceId: number }) {
  // Previous snapshot (counters + timestamp) for client-side rate computation.
  const prev = useRef<{ at: number; by: Record<string, Iface> } | null>(null);

  const { data, dataUpdatedAt } = useQuery({
    queryKey: ["status", instanceId],
    queryFn: () => api.get<SystemStatus>(`/api/instances/${instanceId}/status`),
    refetchInterval: 30_000,
  });

  const cur: Record<string, Iface> = {};
  (data?.interfaces ?? []).forEach((i) => {
    cur[i.name] = i;
  });

  // Store this snapshot AFTER render so the rate below uses the prior one.
  useEffect(() => {
    if (data) prev.current = { at: dataUpdatedAt, by: cur };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataUpdatedAt]);

  if (!data || data.interfaces.length === 0) return null;

  const p = prev.current;
  const dt = p ? (dataUpdatedAt - p.at) / 1000 : 0;
  const rate = (name: string, key: "bytes_received" | "bytes_transmitted"): number | null => {
    if (!p || dt <= 0 || !p.by[name]) return null;
    const delta = cur[name][key] - p.by[name][key];
    return delta >= 0 ? delta / dt : 0;
  };

  return (
    <section className="mt-8">
      <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-400">
        <Network className="h-4 w-4" /> Interfaces
      </h2>
      <div className="mt-3 overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-left text-xs text-slate-500">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">RX</th>
              <th className="px-3 py-2">TX</th>
              <th className="px-3 py-2">Errors</th>
            </tr>
          </thead>
          <tbody>
            {data.interfaces.map((i) => {
              const up = i.status.toLowerCase().includes("up");
              const errs = (i.in_errors ?? 0) + (i.out_errors ?? 0) + (i.collisions ?? 0);
              // Prefer the server-derived rate (agent mode, where two cached
              // /status reads are identical and a client delta would be 0); fall
              // back to the client delta for the direct-poll path (rate = -1).
              const rxBps = i.rx_rate >= 0 ? i.rx_rate : rate(i.name, "bytes_received");
              const txBps = i.tx_rate >= 0 ? i.tx_rate : rate(i.name, "bytes_transmitted");
              return (
                <tr key={i.name} className="border-t border-slate-800">
                  <td className="px-3 py-2 font-medium">{i.name}</td>
                  <td className="px-3 py-2">
                    <span className={up ? "text-emerald-400" : "text-slate-500"}>
                      {up ? "up" : i.status || "down"}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">{i.address || "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs">↓ {fmtRate(rxBps)}</td>
                  <td className="px-3 py-2 font-mono text-xs">↑ {fmtRate(txBps)}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {errs === 0 ? (
                      <span className="text-slate-600">—</span>
                    ) : (
                      <span
                        className={isErrSkipped(i.name) ? "text-slate-500" : "text-amber-400"}
                        title={
                          isErrSkipped(i.name)
                            ? "in / out / collisions (virtual iface — not a wire fault)"
                            : "in / out / collisions"
                        }
                      >
                        {i.in_errors}/{i.out_errors}/{i.collisions}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
