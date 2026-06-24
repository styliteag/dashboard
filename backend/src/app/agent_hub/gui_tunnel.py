"""In-container TCP forwarder for the GUI proxy (see §18).

Binds a local port and bridges each accepted connection straight to a firewall's
GUI port through its agent — the same tunnel as the local CLI, but hosted inside
the backend container so the user needs no local tool. A reverse proxy (Caddy)
sits in front to give a per-instance origin + a valid TLS cert (per-port in dev,
wildcard subdomain in prod); the browser then speaks to the firewall transparently.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import uuid

import structlog

from app.agent_hub.hub import hub

log = structlog.get_logger("app.gui_tunnel")


async def _bridge(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, instance_id: int
) -> None:
    """Pipe one accepted socket to the firewall GUI through the instance's agent."""
    agent = hub.get(instance_id)
    if agent is None:
        writer.close()
        return

    stream = uuid.uuid4().hex
    queue = hub.open_tunnel(stream)
    try:
        await agent.ws.send_json({"type": "tunnel", "op": "open", "stream": stream})

        async def sock_to_agent() -> None:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await agent.ws.send_json(
                    {
                        "type": "tunnel",
                        "op": "data",
                        "stream": stream,
                        "data": base64.b64encode(data).decode(),
                    }
                )

        async def agent_to_sock() -> None:
            while True:
                frame = await queue.get()
                if frame.get("op") == "close":
                    return
                if frame.get("op") == "data":
                    writer.write(base64.b64decode(frame.get("data", "")))
                    await writer.drain()

        pumps = [asyncio.create_task(sock_to_agent()), asyncio.create_task(agent_to_sock())]
        await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        for task in pumps:
            task.cancel()
    except Exception:  # noqa: BLE001 — never let one connection take down the listener
        log.exception("gui_tunnel.bridge_error", instance_id=instance_id, stream=stream)
    finally:
        hub.close_tunnel(stream)
        with contextlib.suppress(Exception):
            await agent.ws.send_json({"type": "tunnel", "op": "close", "stream": stream})
        with contextlib.suppress(Exception):
            writer.close()


async def start_gui_tunnel(instance_id: int, host: str, port: int) -> asyncio.AbstractServer:
    """Start a TCP listener that forwards to instance_id's GUI through its agent."""
    server = await asyncio.start_server(lambda r, w: _bridge(r, w, instance_id), host, port)
    log.info("gui_tunnel.listening", instance_id=instance_id, host=host, port=port)
    return server


def parse_tunnel_spec(spec: str) -> list[tuple[int, int]]:
    """Parse `DASH_GUI_TUNNELS` like "3:14444,4:14445" into [(instance, port), …]."""
    out: list[tuple[int, int]] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        inst, _, port = part.partition(":")
        with contextlib.suppress(ValueError):
            out.append((int(inst), int(port)))
    return out


# Each instance gets a STABLE forwarder port (never reused for another instance),
# so a per-origin cookie can never leak across firewalls (see §18 + the auth gate).
_FORWARDER_BASE_PORT = 14400


class GuiTunnelManager:
    """Starts one forwarder per instance on demand, on a stable convention port."""

    def __init__(self) -> None:
        self._servers: dict[int, asyncio.AbstractServer] = {}

    @staticmethod
    def port_for(instance_id: int) -> int:
        return _FORWARDER_BASE_PORT + instance_id

    async def ensure(self, instance_id: int) -> int:
        """Ensure a forwarder is running for this instance; return its port."""
        if instance_id not in self._servers:
            self._servers[instance_id] = await start_gui_tunnel(
                instance_id, "0.0.0.0", self.port_for(instance_id)
            )
        return self.port_for(instance_id)

    def close_all(self) -> None:
        for server in self._servers.values():
            server.close()
        self._servers.clear()


gui_tunnels = GuiTunnelManager()
