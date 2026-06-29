"""Tests for the GUI-proxy TCP tunnel manager (§18).

The TCP socket (asyncio.open_connection) is stubbed; these cover the frame
contract: open spawns a pump that forwards socket bytes as `data` frames and a
`close` on EOF, inbound `data` writes to the socket, and shutdown cancels pumps.
Proven live on .199 (curl/HTTP-2 through the tunnel); these guard the framing.
"""

from __future__ import annotations

import asyncio
import base64
import json

import orbit_agent as agent


class _FakeWS:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, text: str) -> None:
        self.sent.append(json.loads(text))


class _FakeReader:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def read(self, _n: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _FakeWriter:
    def __init__(self) -> None:
        self.data = b""
        self.closed = False

    def write(self, d: bytes) -> None:
        self.data += d

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


def _stub_connect(monkeypatch, reader, writer):
    async def fake_open(host, port):
        return reader, writer

    monkeypatch.setattr(agent.asyncio, "open_connection", fake_open)


async def test_open_pumps_socket_bytes_then_close(monkeypatch) -> None:
    ws = _FakeWS()
    reader, writer = _FakeReader([b"hello"]), _FakeWriter()
    _stub_connect(monkeypatch, reader, writer)

    tm = agent._TunnelManager(ws, "127.0.0.1", 4444)
    await tm.handle({"op": "open", "stream": "s1"})
    await asyncio.sleep(0.02)  # let the pump task run to EOF

    ops = [(f["op"], f.get("data")) for f in ws.sent]
    assert ("data", base64.b64encode(b"hello").decode()) in ops
    assert any(op == "close" for op, _ in ops)


async def test_inbound_data_written_to_socket(monkeypatch) -> None:
    ws = _FakeWS()
    reader, writer = _FakeReader([]), _FakeWriter()  # no socket→ws traffic
    _stub_connect(monkeypatch, reader, writer)

    tm = agent._TunnelManager(ws, "127.0.0.1", 4444)
    await tm.handle({"op": "open", "stream": "s1"})
    await tm.handle({"op": "data", "stream": "s1", "data": base64.b64encode(b"xyz").decode()})
    assert writer.data == b"xyz"


async def test_data_for_unknown_stream_is_ignored() -> None:
    tm = agent._TunnelManager(_FakeWS(), "127.0.0.1", 4444)
    await tm.handle({"op": "data", "stream": "ghost", "data": "AAAA"})  # must not raise


async def test_open_failure_sends_close(monkeypatch) -> None:
    ws = _FakeWS()

    async def boom(host, port):
        raise OSError("connection refused")

    monkeypatch.setattr(agent.asyncio, "open_connection", boom)
    tm = agent._TunnelManager(ws, "127.0.0.1", 4444)
    await tm.handle({"op": "open", "stream": "s1"})
    assert ws.sent and ws.sent[-1]["op"] == "close"


async def test_shutdown_closes_sockets(monkeypatch) -> None:
    writer = _FakeWriter()
    _stub_connect(monkeypatch, _FakeReader([]), writer)
    tm = agent._TunnelManager(_FakeWS(), "127.0.0.1", 4444)
    await tm.handle({"op": "open", "stream": "s1"})
    tm.shutdown()
    assert writer.closed
