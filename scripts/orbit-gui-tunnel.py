#!/usr/bin/env python3
"""Local GUI tunnel for Orbit — reach a NAT'd firewall's web GUI through its agent.

The dashboard can't path-proxy the GUI (absolute URLs escape any prefix), so this
forwards a LOCAL port to the firewall's GUI port over the agent's WebSocket as a raw
TCP tunnel. The browser speaks TLS end-to-end with the firewall, so AJAX/forms/live
views all work — no HTML rewriting. See docs/agent-architecture.md §18.

Dependency: websockets (`pip install websockets`, or run via `uv run`).

Usage:
  python scripts/orbit-gui-tunnel.py --dashboard http://10.20.0.24:8000 --instance 3
  # then open https://localhost:8443/ and accept the firewall's self-signed cert
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import urllib.request

import websockets


def login(base: str, user: str, password: str) -> str:
    """Log in and return the `dash_session=…` cookie string."""
    data = json.dumps({"username": user, "password": password}).encode()
    req = urllib.request.Request(
        f"{base}/api/auth/login", data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — operator-supplied URL
        for part in resp.headers.get("Set-Cookie", "").split(";"):
            if part.strip().startswith("dash_session="):
                return part.strip()
    raise SystemExit("login failed: no session cookie returned")


async def _serve(ws_url: str, port: int, cookie: str) -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            ws = await websockets.connect(
                ws_url, additional_headers={"Cookie": cookie}, max_size=None
            )
        except Exception as exc:  # noqa: BLE001
            print("tunnel connect failed:", exc)
            writer.close()
            return

        async def tcp_to_ws() -> None:
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await ws.send(data)
            except Exception:  # noqa: BLE001
                pass

        async def ws_to_tcp() -> None:
            try:
                async for msg in ws:
                    if isinstance(msg, (bytes, bytearray)):
                        writer.write(msg)
                        await writer.drain()
            except Exception:  # noqa: BLE001
                pass

        pumps = [asyncio.create_task(tcp_to_ws()), asyncio.create_task(ws_to_tcp())]
        await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        for task in pumps:
            task.cancel()
        try:
            await ws.close()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    print(f"GUI tunnel ready → open https://localhost:{port}/  (accept the self-signed cert)")
    async with server:
        await server.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description="Tunnel a firewall web GUI through its Orbit agent")
    ap.add_argument("--dashboard", default=os.environ.get("DASH_URL", "http://localhost:8000"))
    ap.add_argument("--instance", required=True, help="instance id of the target firewall")
    ap.add_argument("--port", type=int, default=8443, help="local port to listen on")
    ap.add_argument("--user", default=os.environ.get("DASH_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("DASH_PASSWORD"))
    args = ap.parse_args()

    base = args.dashboard.rstrip("/")
    password = args.password or getpass.getpass("Dashboard password: ")
    cookie = login(base, args.user, password)
    ws_url = base.replace("https://", "wss://").replace("http://", "ws://") + f"/api/ws/tunnel/{args.instance}"
    try:
        asyncio.run(_serve(ws_url, args.port, cookie))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
