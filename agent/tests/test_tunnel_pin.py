"""The GUI tunnel must connect only to the configured local target.

A malicious/compromised dashboard could otherwise send an "open" frame with an
arbitrary host/port and turn the root agent into a TCP pivot into the box's LAN.
"""

from __future__ import annotations

import orbit_agent as agent
import pytest


class _FakeWS:
    async def send(self, _data: str) -> None:
        return None


@pytest.mark.asyncio
async def test_tunnel_open_ignores_server_supplied_host_port(monkeypatch) -> None:
    seen: dict[str, object] = {}

    async def fake_open(host, port):
        seen["host"] = host
        seen["port"] = port
        raise OSError("stop before real I/O")  # _open handles this, sends close

    monkeypatch.setattr(agent.asyncio, "open_connection", fake_open)

    tm = agent._TunnelManager(_FakeWS(), host="127.0.0.1", port=4444)
    # Attacker-controlled destination in the frame — must be ignored.
    await tm.handle({"op": "open", "stream": "1", "host": "10.20.1.50", "port": 22})

    assert seen == {"host": "127.0.0.1", "port": 4444}
