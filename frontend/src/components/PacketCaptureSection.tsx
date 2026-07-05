import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Play, Download, ExternalLink } from "lucide-react";
import { api } from "../lib/api";
import type { SystemStatus } from "../lib/types";

interface Props {
  instanceId: number;
}

interface CaptureResult {
  capture_id: string;
  meta: {
    bytes: number;
    truncated: boolean;
    interface: string;
    filter: string;
    max_seconds: number;
    max_bytes: number;
  };
}

export default function PacketCaptureSection({ instanceId }: Props) {
  const [iface, setIface] = useState("em0");
  const [filter, setFilter] = useState("");
  const [seconds, setSeconds] = useState(30);
  const [maxBytes, setMaxBytes] = useState(1_000_000);
  const [result, setResult] = useState<CaptureResult | null>(null);

  const { data: status } = useQuery<SystemStatus>({
    queryKey: ["status", instanceId],
    queryFn: () => api.get(`/api/instances/${instanceId}/status`),
  });

  const interfaces = (status?.interfaces ?? []).map((i) => i.name).filter(Boolean);
  const currentIface = interfaces.length ? (interfaces.includes(iface) ? iface : interfaces[0]) : iface;

  const capMut = useMutation({
    mutationFn: () =>
      api.post<CaptureResult>(`/api/captures/instances/${instanceId}`, {
        interface: currentIface,
        filter: filter.trim(),
        max_seconds: seconds,
        max_bytes: maxBytes,
      }),
    onSuccess: (r) => setResult(r),
  });

  const start = () => {
    setResult(null);
    capMut.mutate();
  };

  const downloadUrl = result ? `/api/captures/${result.capture_id}/pcap` : "";
  const viewerUrl = result ? `/capture/${result.capture_id}` : "";

  return (
    <section className="mt-6 space-y-4">
      <h2 className="text-sm font-semibold text-slate-400 flex items-center gap-2">
        <Play className="h-4 w-4" /> Remote Packet Capture (via agent)
      </h2>

      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label className="block">
            <span className="text-xs text-slate-400">Interface</span>
            <select
              value={currentIface}
              onChange={(e) => setIface(e.target.value)}
              className="mt-1 w-full rounded bg-slate-950 border border-slate-700 px-2 py-1 text-sm"
              disabled={capMut.isPending}
            >
              {(interfaces.length ? interfaces : [currentIface]).map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
            <p className="text-[10px] text-slate-500 mt-0.5">From live ifconfig on the box.</p>
          </label>

          <label className="block">
            <span className="text-xs text-slate-400">BPF Filter (optional)</span>
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="host 192.168.1.10 and port 443"
              className="mt-1 w-full rounded bg-slate-950 border border-slate-700 px-2 py-1 text-sm font-mono"
              disabled={capMut.isPending}
            />
          </label>

          <label className="block">
            <span className="text-xs text-slate-400">Max duration (seconds)</span>
            <input
              type="number"
              min={5}
              max={600}
              value={seconds}
              onChange={(e) => setSeconds(Math.max(5, Math.min(600, Number(e.target.value) || 30)))}
              className="mt-1 w-full rounded bg-slate-950 border border-slate-700 px-2 py-1 text-sm"
              disabled={capMut.isPending}
            />
          </label>

          <label className="block">
            <span className="text-xs text-slate-400">Max size (bytes)</span>
            <select
              value={maxBytes}
              onChange={(e) => setMaxBytes(Number(e.target.value))}
              className="mt-1 w-full rounded bg-slate-950 border border-slate-700 px-2 py-1 text-sm"
              disabled={capMut.isPending}
            >
              <option value={256000}>256 KB</option>
              <option value={512000}>512 KB</option>
              <option value={1000000}>1 MB</option>
              <option value={2097152}>2 MB</option>
              <option value={5242880}>5 MB</option>
              <option value={10485760}>10 MB</option>
              <option value={20971520}>20 MB</option>
            </select>
            <p className="text-[10px] text-slate-500 mt-0.5">Hard-capped on the firewall for safety. Live captures have no fixed time limit (until you stop or close the tab).</p>
          </label>
        </div>

        <button
          onClick={start}
          disabled={capMut.isPending}
          className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-60"
        >
          <Play className="h-4 w-4" /> Start Snapshot (bounded)
        </button>
        <button
          onClick={() => {
            const u = new URLSearchParams({
              live: "1",
              interface: currentIface,
              filter: filter.trim(),
            });
            window.open(`/capture/${instanceId}?${u.toString()}`, "_blank");
          }}
          className="inline-flex items-center gap-2 rounded-lg border border-emerald-600 px-4 py-1.5 text-sm font-medium text-emerald-300 hover:bg-emerald-950"
        >
          <Play className="h-4 w-4" /> Start LIVE stream (new tab)
        </button>

        {capMut.isPending && <div className="text-sm text-slate-400">Capturing on the firewall…</div>}
        {capMut.error && <div className="text-sm text-red-400">{(capMut.error as any)?.message || "failed"}</div>}

        {result && (
          <div className="mt-2 rounded border border-emerald-800/40 bg-emerald-950/20 p-3 text-sm space-y-2">
            <div>
              Captured <span className="font-mono">{result.meta.bytes}</span> bytes on <span className="font-mono">{result.meta.interface}</span>
              {result.meta.truncated && <span className="ml-2 text-amber-400">(truncated at limit)</span>}
            </div>
            {result.meta.filter && <div className="text-xs text-slate-400">filter: {result.meta.filter}</div>}

            <div className="flex flex-wrap gap-2 pt-1">
              <a
                href={downloadUrl}
                className="inline-flex items-center gap-1 rounded bg-slate-800 px-3 py-1 text-xs hover:bg-slate-700"
              >
                <Download className="h-3.5 w-3.5" /> Download PCAP
              </a>
              <button
                onClick={() => window.open(viewerUrl, "_blank")}
                className="inline-flex items-center gap-1 rounded bg-emerald-700 px-3 py-1 text-xs hover:bg-emerald-600"
              >
                <ExternalLink className="h-3.5 w-3.5" /> View packets in new tab
              </button>
            </div>
            <div className="text-[10px] text-slate-500">Capture id: {result.capture_id} (expires in ~1h)</div>
          </div>
        )}
      </div>

      <p className="text-xs text-slate-500">
        Runs <code>tcpdump</code> on the firewall via the agent (bounded, no SSH needed). Open the viewer in a new tab for a clean packet list + hex view.
      </p>
    </section>
  );
}
