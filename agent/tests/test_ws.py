"""Tests for the agent's stdlib WebSocket client (DR-4).

Two layers:
  1. Deterministic framing/handshake unit tests (RFC 6455 vectors).
  2. Interop integration: connect the hand-rolled client to a reference
     ``websockets`` server and exchange text / large / ping / close frames.
     The backend runs on uvicorn+websockets, so interop here ≈ interop there.
"""

from __future__ import annotations

import asyncio
import struct

import opnsense_agent as agent
import pytest
import websockets

# --- unit: handshake + framing ------------------------------------------------


def test_accept_key_matches_rfc6455_example() -> None:
    # RFC 6455 §1.3 worked example.
    assert agent._ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def _server_decode(frame: bytes) -> tuple[int, bytes]:
    """Decode a client (masked) frame the way a server would, for round-trip tests."""
    opcode = frame[0] & 0x0F
    assert frame[0] & 0x80, "FIN must be set"
    masked = bool(frame[1] & 0x80)
    assert masked, "client frames MUST be masked"
    length = frame[1] & 0x7F
    off = 2
    if length == 126:
        (length,) = struct.unpack("!H", frame[off : off + 2])
        off += 2
    elif length == 127:
        (length,) = struct.unpack("!Q", frame[off : off + 8])
        off += 8
    mask = frame[off : off + 4]
    off += 4
    payload = bytes(b ^ mask[i & 3] for i, b in enumerate(frame[off : off + length]))
    return opcode, payload


@pytest.mark.parametrize("size", [0, 5, 125, 126, 200, 65535, 65536, 100000])
def test_encode_frame_roundtrip(size: int) -> None:
    payload = bytes(i & 0xFF for i in range(size))
    opcode, decoded = _server_decode(agent._encode_frame(agent._OP_TEXT, payload))
    assert opcode == agent._OP_TEXT
    assert decoded == payload


def test_encode_frame_uses_extended_lengths() -> None:
    # 7-bit length for <126, 16-bit marker for <65536, 64-bit marker beyond.
    assert agent._encode_frame(agent._OP_TEXT, b"x")[1] & 0x7F == 1
    assert agent._encode_frame(agent._OP_TEXT, b"x" * 200)[1] & 0x7F == 126
    assert agent._encode_frame(agent._OP_TEXT, b"x" * 70000)[1] & 0x7F == 127


# --- integration: interop with a reference websockets server ------------------


@pytest.mark.asyncio
async def test_interop_echo_text_and_large() -> None:
    async def handler(conn):
        async for message in conn:
            await conn.send(message)

    async with websockets.serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        ws = await agent.ws_connect(
            f"ws://127.0.0.1:{port}/ws", headers={"X-Test": "1"}, max_size=10 * 1024 * 1024
        )
        try:
            await ws.send("hello")
            assert await ws.recv() == "hello"

            big = "z" * 200_000  # exercises 64-bit length + reassembly of server fragments
            await ws.send(big)
            assert await ws.recv() == big
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_interop_server_ping_is_answered() -> None:
    pong_seen = asyncio.Event()

    async def handler(conn):
        pong_waiter = await conn.ping()  # server pings; client must pong
        await pong_waiter
        pong_seen.set()
        await conn.recv()

    async with websockets.serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        ws = await agent.ws_connect(f"ws://127.0.0.1:{port}/ws", headers={}, max_size=1 << 20)
        try:
            # recv() drives the read loop that answers the server ping.
            recv_task = asyncio.create_task(ws.recv())
            await asyncio.wait_for(pong_seen.wait(), timeout=5)
            await ws.send("done")
            recv_task.cancel()
        finally:
            await ws.close()


@pytest.mark.asyncio
async def test_handshake_rejects_non_ws_endpoint() -> None:
    async def serve_plain(reader, writer):
        await reader.readline()
        writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(serve_plain, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        with pytest.raises(agent.WSError):
            await agent.ws_connect(f"ws://127.0.0.1:{port}/nope", headers={}, max_size=1 << 20)
