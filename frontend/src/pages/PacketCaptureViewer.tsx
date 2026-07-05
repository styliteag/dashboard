import { useEffect, useMemo, useRef, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Download, Search } from "lucide-react";
import { api, apiErrorText } from "../lib/api";

interface Packet {
  idx: number;
  ts: number | string;
  src: string;
  dst: string;
  proto: string;
  len: number;
  info: string;
  hex: string;
}

interface CaptureData {
  capture_id: string;
  meta: Record<string, unknown>;
  packets: Packet[];
}

export default function PacketCaptureViewer() {
  const { capId } = useParams<{ capId: string }>();
  const [search] = useSearchParams();
  const isLive = search.get("live") === "1";
  const liveIface = search.get("interface") || "";
  const liveFilter = search.get("filter") || "";

  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<Packet | null>(null);
  const [livePackets, setLivePackets] = useState<Packet[]>([]);
  const [liveMeta, setLiveMeta] = useState<Record<string, unknown>>({});
  const [bytesReceived, setBytesReceived] = useState(0);
  const [captureStarted, setCaptureStarted] = useState(false);
  const [captureError, setCaptureError] = useState<string | null>(null);
  const [isStopped, setIsStopped] = useState(false);
  const accumulatedPcapRef = useRef<Uint8Array>(new Uint8Array(0));
  const parseOffsetRef = useRef(0); // how far we've parsed in the accumulated buffer
  const packetIdxRef = useRef(1);
  const wsRef = useRef<WebSocket | null>(null);

  // Simple streaming pcap parser (global header 24 bytes + per-packet 16B header + data)
  const parseIncomingPcap = () => {
    const buf = accumulatedPcapRef.current;
    let offset = parseOffsetRef.current;
    const newPkts: Packet[] = [];

    // skip global header (first time)
    if (offset === 0 && buf.length >= 24) {
      offset = 24;
    }

    let currentIdx = packetIdxRef.current;

    while (offset + 16 <= buf.length) {
      const inclLen = new DataView(buf.buffer, buf.byteOffset + offset + 8, 4).getUint32(0, true);
      if (offset + 16 + inclLen > buf.length) break; // not a full packet yet

      const packetBytes = buf.slice(offset + 16, offset + 16 + inclLen);
      const tsSec = new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, true);
      const tsUsec = new DataView(buf.buffer, buf.byteOffset + offset + 4, 4).getUint32(0, true);
      const ts = tsSec + tsUsec / 1_000_000;

      const summary = summarizePacket(packetBytes, ts, currentIdx);
      newPkts.push(summary);

      offset += 16 + inclLen;
      currentIdx++;
    }

    if (newPkts.length > 0) {
      parseOffsetRef.current = offset;
      packetIdxRef.current = currentIdx;
      setLivePackets((prev) => [...prev, ...newPkts].slice(-1500));
    }
  };

  const summarizePacket = (frame: Uint8Array, ts: number, idx: number): Packet => {
    if (frame.length < 14) {
      return {
        idx,
        ts: ts.toFixed(3),
        src: "",
        dst: "",
        proto: "RAW",
        len: frame.length,
        info: "",
        hex: toHex(frame.slice(0, 64)),
      };
    }
    const ethType = (frame[12] << 8) | frame[13];
    if (ethType === 0x0800) {
      // IPv4
      return parseIPv4(frame.slice(14), ts, idx, frame.length);
    }
    if (ethType === 0x86dd) {
      return {
        idx,
        ts: ts.toFixed(3),
        src: "",
        dst: "",
        proto: "IPv6",
        len: frame.length,
        info: "",
        hex: toHex(frame.slice(0, 64)),
      };
    }
    return {
      idx,
      ts: ts.toFixed(3),
      src: "",
      dst: "",
      proto: "ETH",
      len: frame.length,
      info: `0x${ethType.toString(16)}`,
      hex: toHex(frame.slice(0, 64)),
    };
  };

  const parseIPv4 = (ip: Uint8Array, ts: number, idx: number, wireLen: number): Packet => {
    if (ip.length < 20)
      return {
        idx,
        ts: ts.toFixed(3),
        src: "",
        dst: "",
        proto: "IP",
        len: wireLen,
        info: "",
        hex: toHex(ip.slice(0, 64)),
      };
    const ihl = (ip[0] & 0x0f) * 4;
    const proto = ip[9];
    const src = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`;
    const dst = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
    const l4 = ip.slice(ihl);
    if (proto === 6 && l4.length >= 4) {
      // TCP
      const sport = (l4[0] << 8) | l4[1];
      const dport = (l4[2] << 8) | l4[3];
      const flags = l4.length > 13 ? l4[13] : 0;
      let fl = "";
      if (flags & 0x02) fl += "S";
      if (flags & 0x10) fl += "A";
      if (flags & 0x01) fl += "F";
      if (flags & 0x04) fl += "R";
      let info = `${sport}→${dport} ${fl || ""}`.trim();
      if ([80, 443, 9922].includes(dport) || [80, 443, 9922].includes(sport)) info += " HTTP/TLS?";
      return {
        idx,
        ts: ts.toFixed(3),
        src: `${src}:${sport}`,
        dst: `${dst}:${dport}`,
        proto: "TCP",
        len: wireLen,
        info,
        hex: toHex(ip.slice(0, 96)),
      };
    }
    if (proto === 17 && l4.length >= 4) {
      // UDP
      const sport = (l4[0] << 8) | l4[1];
      const dport = (l4[2] << 8) | l4[3];
      let info = `${sport}→${dport}`;
      if (dport === 53 || sport === 53) info += " DNS/mDNS";
      return {
        idx,
        ts: ts.toFixed(3),
        src: `${src}:${sport}`,
        dst: `${dst}:${dport}`,
        proto: "UDP",
        len: wireLen,
        info,
        hex: toHex(ip.slice(0, 80)),
      };
    }
    return {
      idx,
      ts: ts.toFixed(3),
      src,
      dst,
      proto: `IP/${proto}`,
      len: wireLen,
      info: "",
      hex: toHex(ip.slice(0, 64)),
    };
  };

  const toHex = (b: Uint8Array) =>
    Array.from(b)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join(" ");

  // Static (one-shot) mode
  const {
    data: staticData,
    isLoading,
    error,
  } = useQuery<CaptureData>({
    queryKey: ["capture-view", capId],
    queryFn: () => api.get<CaptureData>(`/api/captures/${capId}/packets`),
    enabled: !!capId && !isLive,
  });

  const staticPackets = staticData?.packets ?? [];

  const allPackets = isLive ? livePackets : staticPackets;
  const meta = (isLive ? liveMeta : staticData?.meta || {}) as Record<
    string,
    string | number | boolean | undefined
  >;

  const filtered = useMemo(() => {
    const q = filter.toLowerCase().trim();
    if (!q) return allPackets;
    return allPackets.filter(
      (p) =>
        (p.src || "").toLowerCase().includes(q) ||
        (p.dst || "").toLowerCase().includes(q) ||
        (p.info || "").toLowerCase().includes(q) ||
        (p.proto || "").toLowerCase().includes(q),
    );
  }, [allPackets, filter]);

  useEffect(() => {
    if (!selected && filtered.length) setSelected(filtered[0]);
  }, [filtered, selected]);

  // LIVE MODE: connect to WS stream
  useEffect(() => {
    if (!isLive || !capId) return;

    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const qs = new URLSearchParams({ interface: liveIface, filter: liveFilter });
    const wsUrl = `${proto}://${window.location.host}/api/ws/capture/${capId}?${qs.toString()}`;
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => {
      setLiveMeta({ interface: liveIface, filter: liveFilter, live: true });
    };

    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        const chunk = new Uint8Array(ev.data);

        // accumulate raw pcap for save + parsing
        const acc = accumulatedPcapRef.current;
        const merged = new Uint8Array(acc.length + chunk.length);
        merged.set(acc);
        merged.set(chunk, acc.length);
        accumulatedPcapRef.current = merged;

        setBytesReceived((prev) => prev + chunk.length);

        // Try to parse as many full packets as we can from the stream
        parseIncomingPcap();
      } else if (typeof ev.data === "string") {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "started") {
            setCaptureStarted(true);
          } else if (msg.type === "error") {
            setCaptureError(msg.message || "unknown error");
          }
        } catch {
          return;
        }
      }
    };

    ws.onclose = () => {
      if (isLive) setIsStopped(true);
    };

    ws.onerror = () => {
      // error
    };

    const onBeforeUnload = () => {
      if (wsRef.current && isLive) {
        try {
          wsRef.current.send(JSON.stringify({ type: "stop" }));
        } catch {
          return;
        }
        wsRef.current.close();
      }
    };
    window.addEventListener("beforeunload", onBeforeUnload);

    return () => {
      window.removeEventListener("beforeunload", onBeforeUnload);
      if (wsRef.current) {
        try {
          if (isLive) wsRef.current.send(JSON.stringify({ type: "stop" }));
        } catch {
          return;
        }
        wsRef.current.close();
      }
      wsRef.current = null;
    };
    // The parser reads from refs and appends to state; changing its identity must
    // not reconnect the live capture websocket.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLive, capId, liveIface, liveFilter]);

  const stopLive = () => {
    if (wsRef.current) {
      wsRef.current.send(JSON.stringify({ type: "stop" }));
      wsRef.current.close();
    }
    setIsStopped(true);
  };

  const downloadLive = () => {
    const buf = accumulatedPcapRef.current;
    const copy = new Uint8Array(buf); // ensure ArrayBuffer
    const blob = new Blob([copy], { type: "application/vnd.tcpdump.pcap" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `live-capture-${capId || Date.now()}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadUrl = isLive ? "" : `/api/captures/${capId}/pcap`;

  if (!capId && !isLive) return <div className="p-8">Missing capture id</div>;

  return (
    <div className="min-h-screen bg-[#0b0f14] text-slate-200 p-4 md:p-6 font-sans">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-xl font-semibold flex items-center gap-2">
              Packet Capture {isLive ? "— LIVE" : "Viewer"}
              {isLive && !isStopped && (
                <span className="text-emerald-400 text-sm animate-pulse">● LIVE</span>
              )}
              {isLive && isStopped && <span className="text-slate-400 text-sm">● STOPPED</span>}
            </h1>
            <div className="text-xs text-slate-500">
              {isLive ? `instance ${capId}` : `id: ${capId}`}
              {liveIface && ` • ${liveIface}`}
            </div>
          </div>
          <div className="flex gap-2">
            {isLive && (
              <>
                <button
                  onClick={stopLive}
                  disabled={isStopped}
                  className={`rounded px-3 py-1.5 text-sm ${isStopped ? "bg-slate-700 text-slate-400 cursor-not-allowed" : "bg-red-600 hover:bg-red-500"}`}
                >
                  {isStopped ? "Stream stopped" : "Stop Stream"}
                </button>
                <button
                  onClick={downloadLive}
                  className="inline-flex items-center gap-2 rounded bg-emerald-600 px-3 py-1.5 text-sm hover:bg-emerald-500"
                >
                  <Download className="h-4 w-4" /> Save Buffer as PCAP
                </button>
              </>
            )}
            {!isLive && (
              <a
                href={downloadUrl}
                className="inline-flex items-center gap-2 rounded bg-emerald-600 px-3 py-1.5 text-sm hover:bg-emerald-500"
              >
                <Download className="h-4 w-4" /> Download PCAP
              </a>
            )}
          </div>
        </div>

        {meta && (
          <div className="mb-3 text-xs text-slate-400 flex flex-wrap gap-x-4">
            <span>
              iface: <span className="font-mono text-slate-300">{meta.interface || liveIface}</span>
            </span>
            {(meta.filter || liveFilter) && (
              <span>
                filter:{" "}
                <span className="font-mono text-slate-300">{meta.filter || liveFilter}</span>
              </span>
            )}
            <span>
              bytes received: <span className="font-mono text-emerald-300">{bytesReceived}</span>
            </span>
            <span>items: {filtered.length}</span>
            {isLive && !isStopped && <span className="text-emerald-400">streaming from agent</span>}
            {isLive && isStopped && <span className="text-slate-400">stream stopped</span>}
            {isLive && captureStarted && !isStopped && (
              <span className="text-emerald-400"> (capture started on box)</span>
            )}
            {isLive && isStopped && captureStarted && (
              <span className="text-slate-400"> (stopped)</span>
            )}
            {isLive && captureError && <span className="text-red-400"> error: {captureError}</span>}
          </div>
        )}

        <div className="flex items-center gap-2 mb-2">
          <Search className="h-4 w-4 text-slate-400" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by IP, port, info…"
            className="flex-1 bg-slate-950 border border-slate-700 rounded px-2 py-1 text-sm"
          />
          {isLive && !isStopped && (
            <span className="text-xs text-emerald-400">
              Live — new packets append automatically
            </span>
          )}
          {isLive && isStopped && (
            <span className="text-xs text-slate-400">
              Stream stopped — packets no longer append
            </span>
          )}
        </div>

        {isLoading && <div className="p-4 text-sm text-slate-400">Loading packets…</div>}
        {error && (
          <div className="p-4 text-sm text-red-400">
            Failed to load: {apiErrorText(error, "capture unavailable")}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
          {/* Packet list */}
          <div className="lg:col-span-3 border border-slate-800 rounded-xl overflow-hidden bg-slate-900/60 max-h-[70vh] overflow-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-950 text-slate-400 sticky top-0">
                <tr>
                  <th className="text-left px-2 py-1 w-8">#</th>
                  <th className="text-left px-2 py-1 w-20">Time</th>
                  <th className="text-left px-2 py-1">Source</th>
                  <th className="text-left px-2 py-1">Dest</th>
                  <th className="text-left px-2 py-1 w-14">Proto</th>
                  <th className="text-right px-2 py-1 w-14">Len</th>
                  <th className="text-left px-2 py-1">Info</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-3 py-4 text-slate-500">
                      {captureError
                        ? `Error from agent: ${captureError}`
                        : isStopped
                          ? "Stream stopped. No more packets will be added."
                          : bytesReceived > 0
                            ? `Got ${bytesReceived} bytes from agent — parsing live pcap stream...`
                            : captureStarted
                              ? "Capture started on the box, but no packets yet (interface may be quiet or filter too strict)."
                              : "No packets yet (waiting for stream)...."}
                    </td>
                  </tr>
                )}
                {filtered.map((p, i) => (
                  <tr
                    key={i}
                    onClick={() => setSelected(p)}
                    className={`cursor-pointer hover:bg-slate-800/60 ${selected?.idx === p.idx ? "bg-emerald-900/30" : ""}`}
                  >
                    <td className="px-2 py-0.5 font-mono text-[10px] text-slate-500">{p.idx}</td>
                    <td className="px-2 py-0.5 font-mono text-xs">
                      {typeof p.ts === "number" ? p.ts.toFixed(3) : p.ts}
                    </td>
                    <td
                      className="px-2 py-0.5 font-mono text-xs text-emerald-300 truncate"
                      title={p.src}
                    >
                      {p.src}
                    </td>
                    <td
                      className="px-2 py-0.5 font-mono text-xs text-sky-300 truncate"
                      title={p.dst}
                    >
                      {p.dst}
                    </td>
                    <td className="px-2 py-0.5">
                      <span className="rounded bg-slate-800 px-1 text-[10px]">{p.proto}</span>
                    </td>
                    <td className="px-2 py-0.5 text-right font-mono text-xs">{p.len}</td>
                    <td className="px-2 py-0.5 text-xs text-slate-300 truncate">{p.info}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Detail pane */}
          <div className="lg:col-span-2 border border-slate-800 rounded-xl bg-slate-900/60 p-3 min-h-[320px]">
            {!selected && (
              <div className="text-sm text-slate-400">Select a packet to inspect its hex.</div>
            )}
            {selected && (
              <>
                <div className="text-sm mb-2">
                  <span className="text-emerald-400">#{selected.idx}</span> {selected.src} →{" "}
                  {selected.dst} <span className="text-slate-400">({selected.proto})</span>
                </div>
                <div className="text-xs mb-1 text-slate-400">Hex dump</div>
                <pre className="bg-black/60 p-2 rounded text-[11px] font-mono overflow-auto max-h-[260px] whitespace-pre-wrap break-all border border-slate-800">
                  {selected.hex}
                </pre>
                <div className="mt-2 text-[10px] text-slate-500">
                  {selected.info} len={selected.len}
                </div>
                <div className="mt-3 text-[10px] text-slate-400">
                  Live stream or snapshot. Download full PCAP for Wireshark.
                </div>
              </>
            )}
          </div>
        </div>

        <div className="mt-6 text-xs text-slate-500">
          {isLive
            ? "Live pcap stream from the agent (tcpdump -U). Packets appear as they arrive. Use Stop + Save Buffer."
            : "Lightweight viewer (basic decode + hex). Download the PCAP for full analysis."}
        </div>
      </div>
    </div>
  );
}
