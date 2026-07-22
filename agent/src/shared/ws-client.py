# to orbit_agent.py AND orbit_agent_linux.py — test_agent_split enforces
# byte equality of this block.
class WSError(Exception):
    """Raised on handshake failure or when the connection is closed."""


def _ws_accept_key(key: str) -> str:
    """Compute the server's Sec-WebSocket-Accept for a client key (RFC 6455 §1.3)."""
    digest = hashlib.sha1((key + _WS_GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def _encode_frame(opcode: int, payload: bytes) -> bytes:
    """Encode a single client frame: FIN=1, masked (clients MUST mask, §5.3)."""
    header = bytearray([0x80 | (opcode & 0x0F)])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header += struct.pack("!H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack("!Q", length)
    mask = os.urandom(4)
    header += mask
    masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return bytes(header) + masked


async def _read_frame(reader: asyncio.StreamReader) -> tuple[bool, int, bytes]:
    """Read one server frame → (fin, opcode, payload). Server frames are unmasked (§5.1)."""
    b0, b1 = await reader.readexactly(2)
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", await reader.readexactly(2))
    elif length == 127:
        (length,) = struct.unpack("!Q", await reader.readexactly(8))
    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length) if length else b""
    if masked and payload:
        payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return fin, opcode, payload


class WebSocket:
    """Minimal asyncio WebSocket client: text frames, ping/pong, close, and
    reassembly of fragmented messages. Concurrent senders are serialized so
    frames never interleave."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, max_size: int):
        self._reader = reader
        self._writer = writer
        self._max_size = max_size
        self._send_lock = asyncio.Lock()
        self._closed = False
        self._last_recv = time.monotonic()  # for dead-peer detection

    def stale_seconds(self) -> float:
        """Seconds since the last frame of any kind arrived from the peer."""
        return time.monotonic() - self._last_recv

    async def _send_frame(self, opcode: int, payload: bytes) -> None:
        async with self._send_lock:
            self._writer.write(_encode_frame(opcode, payload))
            await self._writer.drain()

    async def send(self, text: str) -> None:
        await self._send_frame(_OP_TEXT, text.encode())

    async def ping(self, payload: bytes = b"") -> None:
        await self._send_frame(_OP_PING, payload)

    async def recv(self) -> str:
        """Return the next text message, transparently answering pings and
        reassembling fragments. Raises WSError when the peer closes."""
        buffer = bytearray()
        msg_opcode: int | None = None
        while True:
            fin, opcode, payload = await _read_frame(self._reader)
            self._last_recv = time.monotonic()
            if opcode == _OP_PING:
                await self._send_frame(_OP_PONG, payload)
                continue
            if opcode == _OP_PONG:
                continue
            if opcode == _OP_CLOSE:
                self._closed = True
                raise WSError("connection closed by server")
            if opcode != _OP_CONT:
                msg_opcode = opcode
            buffer += payload
            if len(buffer) > self._max_size:
                raise WSError("message exceeds max_size")
            if fin:
                if msg_opcode == _OP_TEXT:
                    return bytes(buffer).decode()
                buffer = bytearray()  # ignore binary; this agent only speaks JSON text
                msg_opcode = None

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            with contextlib.suppress(OSError, WSError):
                await self._send_frame(_OP_CLOSE, struct.pack("!H", 1000))
        with contextlib.suppress(OSError):
            self._writer.close()


async def ws_connect(url: str, headers: dict[str, str], max_size: int) -> WebSocket:
    """Open a WebSocket connection (ws:// or wss://) and perform the handshake."""
    parts = urlsplit(url)
    secure = parts.scheme == "wss"
    host = parts.hostname or ""
    port = parts.port or (443 if secure else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    ssl_ctx = ssl.create_default_context() if secure else None
    reader, writer = await asyncio.open_connection(
        host, port, ssl=ssl_ctx, server_hostname=host if secure else None
    )

    key = base64.b64encode(os.urandom(16)).decode()
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await writer.drain()

    status_line = await reader.readline()
    if b" 101 " not in status_line and not status_line.startswith(b"HTTP/1.1 101"):
        writer.close()
        raise WSError(f"handshake failed: {status_line.decode(errors='replace').strip()}")
    resp_headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        k, _, v = line.decode(errors="replace").partition(":")
        resp_headers[k.strip().lower()] = v.strip()
    if resp_headers.get("sec-websocket-accept", "") != _ws_accept_key(key):
        writer.close()
        raise WSError("handshake failed: bad Sec-WebSocket-Accept")
    return WebSocket(reader, writer, max_size)
