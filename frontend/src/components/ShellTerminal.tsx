import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

export type ShellStatus = "connecting" | "open" | "closed";

const CLOSE_REASON: Record<number, string> = {
  4401: "Session expired — please log in again.",
  4403: "Shell is disabled on this server (DASH_SHELL_ENABLED is off).",
  4404: "Agent is not connected — no box to attach to.",
};

/**
 * xterm.js terminal wired to a root PTY on the firewall over `/api/ws/shell/{id}`
 * (SPIKE, agent §22). Fills its parent; keystrokes go out as binary, output comes
 * back as binary, window-size changes as a JSON `resize` control frame. Each mount
 * is one independent PTY — render several for several sessions.
 */
export default function ShellTerminal({
  instanceId,
  onStatus,
}: {
  instanceId: number;
  onStatus?: (status: ShellStatus, note?: string) => void;
}) {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: { background: "#0f172a", foreground: "#e2e8f0", cursor: "#34d399" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(mount);
    fit.fit();

    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${window.location.host}/api/ws/shell/${instanceId}`);
    ws.binaryType = "arraybuffer";

    const sendResize = () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };

    ws.onopen = () => {
      onStatus?.("open");
      fit.fit();
      sendResize();
      term.focus();
    };
    ws.onmessage = (ev) => {
      if (ev.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(ev.data));
        return;
      }
      // Text frame = control channel (keepalive). Reply to a server ping so the
      // socket stays warm in both directions; event-driven, so a throttled
      // background tab still answers. Never fed to the terminal.
      if (typeof ev.data === "string") {
        try {
          const m = JSON.parse(ev.data);
          if (m.type === "ping" && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "pong" }));
          }
        } catch {
          /* ignore non-JSON text */
        }
      }
    };
    ws.onclose = (ev) => {
      onStatus?.("closed", CLOSE_REASON[ev.code] ?? "Connection closed.");
      term.write("\r\n\x1b[90m[session closed]\x1b[0m\r\n");
    };

    const enc = new TextEncoder();
    const onData = term.onData((d) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d));
    });

    const ro = new ResizeObserver(() => {
      fit.fit();
      sendResize();
    });
    ro.observe(mount);

    return () => {
      ro.disconnect();
      onData.dispose();
      // Detach handlers before closing: under React StrictMode (dev) the effect
      // runs mount→cleanup→remount, so this socket is superseded. Without this its
      // late onclose would push a stale "closed" status onto the live terminal.
      ws.onopen = ws.onmessage = ws.onclose = null;
      ws.close();
      term.dispose();
    };
  }, [instanceId, onStatus]);

  return <div ref={mountRef} className="h-full w-full" />;
}
