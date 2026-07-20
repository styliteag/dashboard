#!/usr/bin/env python3
"""Find out WHERE a websocket connection to the dashboard gets cut.

Every long-lived feature (the LiveView UI, the agent hub, the browser terminal,
packet capture) rides a websocket that is legitimately idle for stretches. A
reverse proxy or load balancer with a short idle timeout cuts those, and the
symptom points at the wrong layer: the UI drops mid-form, agents flap offline,
a terminal dies while you read its output. The dashboard logs only a fresh
connect, because from its side nothing went wrong.

This probe distinguishes the layers by how the connection ENDS:

  * "CLOSE FRAME code=1002" at ~60s  -> the dashboard itself (Phoenix's own idle
    timeout). Expected, harmless: a real client heartbeats long before that.
  * "eof"/"reset" at any other time  -> something in between cut the TCP stream
    without a websocket close. That is your proxy, and the time it happened is
    its idle timeout.

Run it silent first to find the cut, then with --heartbeat below that interval
to confirm traffic keeps the connection alive.

    python3 scripts/ws_idle_probe.py dash.example.com
    python3 scripts/ws_idle_probe.py dash.example.com --heartbeat 20
    python3 scripts/ws_idle_probe.py localhost --port 8000 --no-tls

Needs no login: it opens the transport only and never joins a LiveView, so an
unauthenticated probe is enough to measure the network path. Stdlib only.

Real finding this was written for: an HAProxy in `mode tcp` with the default
`timeout client/server 30000ms` and no `timeout tunnel` cut every websocket
after 30s of silence. The browser heartbeats every 30s, so each heartbeat raced
the timer — losing one dropped the socket, which read as a random disconnect
roughly every minute. See README "Reverse proxy requirements".
"""

from __future__ import annotations

import argparse
import base64
import os
import socket
import ssl
import struct
import sys
import time

PATH = "/live/websocket?vsn=2.0.0"


def handshake(sock: socket.socket, host: str, scheme: str) -> str:
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {PATH} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: {scheme}://{host}\r\n"
        "\r\n"
    )
    sock.sendall(request.encode())

    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise SystemExit("connection closed during the handshake")
        buf += chunk
    return buf.split(b"\r\n", 1)[0].decode()


def send_text(sock: socket.socket, text: str) -> None:
    """One masked client text frame (clients MUST mask, RFC 6455 §5.3)."""
    payload = text.encode()
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

    n = len(payload)
    if n < 126:
        header = bytes([0x81, 0x80 | n])
    elif n < 65536:
        header = bytes([0x81, 0x80 | 126]) + struct.pack(">H", n)
    else:
        header = bytes([0x81, 0x80 | 127]) + struct.pack(">Q", n)

    sock.sendall(header + mask + masked)


def verdict(kind: str, seconds: float, detail: str = "") -> None:
    print(f"\nt={seconds:.1f}s  {kind}  {detail}".rstrip())
    if kind == "CLOSE FRAME" and "1002" in detail:
        print(
            "-> The dashboard closed it (Phoenix idle timeout, ~60s). This is the\n"
            "   healthy answer: nothing between you and it cut the connection."
        )
    elif kind in ("EOF", "SOCKET ERROR"):
        print(
            f"-> The TCP stream was cut WITHOUT a websocket close frame after\n"
            f"   {seconds:.0f}s. A proxy or load balancer did that, and {seconds:.0f}s is\n"
            "   its idle timeout. See README 'Reverse proxy requirements'."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("host", help="dashboard hostname, e.g. dash.example.com")
    parser.add_argument("--port", type=int, help="default 443 with TLS, 80 without")
    parser.add_argument("--no-tls", action="store_true", help="plain ws:// (dev)")
    parser.add_argument(
        "--heartbeat",
        type=int,
        metavar="SECONDS",
        help="send a phoenix heartbeat this often (0/omitted = stay silent)",
    )
    parser.add_argument(
        "--duration", type=int, default=150, help="observe this long (default 150)"
    )
    args = parser.parse_args()

    tls = not args.no_tls
    port = args.port or (443 if tls else 80)
    scheme = "https" if tls else "http"

    sock = socket.create_connection((args.host, port), timeout=10)
    if tls:
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=args.host)

    status = handshake(sock, args.host, scheme)
    if "101" not in status:
        raise SystemExit(f"no websocket upgrade: {status}")

    started = time.time()
    mode = f"heartbeat every {args.heartbeat}s" if args.heartbeat else "silent"
    print(f"connected to {args.host}:{port} ({mode}), watching for {args.duration}s")

    sock.settimeout(1.0)
    next_beat = started + args.heartbeat if args.heartbeat else None
    ref = 1

    while time.time() - started < args.duration:
        now = time.time()

        if next_beat and now >= next_beat:
            send_text(sock, f'[null,"{ref}","phoenix","heartbeat",{{}}]')
            print(f"t={now - started:6.1f}s  -> heartbeat {ref}")
            ref += 1
            next_beat += args.heartbeat

        try:
            data = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError as exc:
            verdict("SOCKET ERROR", time.time() - started, str(exc))
            return

        elapsed = time.time() - started
        if not data:
            verdict("EOF", elapsed, "server closed the stream, no close frame")
            return

        opcode = data[0] & 0x0F
        if opcode == 0x8:
            code = struct.unpack(">H", data[2:4])[0] if len(data) >= 4 else "?"
            verdict("CLOSE FRAME", elapsed, f"code={code}")
            return
        if opcode == 0x1:
            print(f"t={elapsed:6.1f}s  <- {data[2:][:70].decode(errors='replace')}")

    print(f"\nSURVIVED {args.duration}s, still open.")
    if not args.heartbeat:
        print("-> Nothing in the path cuts idle connections within that window.")
    else:
        print("-> Traffic at this interval keeps the connection alive end to end.")


if __name__ == "__main__":
    sys.exit(main())
