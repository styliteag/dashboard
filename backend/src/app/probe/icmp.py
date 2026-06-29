"""Stdlib ICMP echo — no iputils, no subprocess.

Prefers an unprivileged ``SOCK_DGRAM``/``IPPROTO_ICMP`` socket (works when the
kernel's ``ping_group_range`` permits it — the Docker default), falling back to a
raw ``SOCK_RAW`` socket (the container's default capability set includes
NET_RAW). Both were verified to reach the lab boxes from the backend container.

``ping()`` blocks on a socket and must be called via ``asyncio.to_thread`` from
async code (the runner does this).
"""

from __future__ import annotations

import os
import socket
import struct
import time

_ICMP_ECHO_REQUEST = 8
_ICMP_ECHO_REPLY = 0
_IP_HEADER_LEN = 20  # raw sockets prepend the IPv4 header; DGRAM sockets don't


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071) over ``data``. 16-bit one's-complement sum."""
    total = 0
    for i in range(0, len(data) - len(data) % 2, 2):
        total += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        total += data[-1] << 8
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo_request(ident: int, seq: int, payload: bytes = b"orbit-probe") -> bytes:
    """A complete ICMP echo-request datagram with a valid checksum."""
    ident &= 0xFFFF
    seq &= 0xFFFF
    head = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    chk = checksum(head + payload)
    return struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, chk, ident, seq) + payload


def icmp_type(packet: bytes, *, raw: bool) -> int | None:
    """ICMP ``type`` byte of a received packet, or None if too short.

    Raw sockets hand back the IPv4 header in front of the ICMP message; datagram
    sockets hand back the ICMP message directly.
    """
    icmp = packet[_IP_HEADER_LEN:] if raw else packet
    return icmp[0] if icmp else None


def _open_socket() -> tuple[socket.socket, bool]:
    """Open an ICMP socket; return (socket, is_raw). DGRAM preferred, RAW fallback."""
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP), False
    except (PermissionError, OSError):
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP), True


def ping(host: str, timeout: float = 1.0, seq: int = 1) -> float | None:
    """Round-trip time in ms for one ICMP echo to ``host``, or None on no reply.

    Blocking — call via ``asyncio.to_thread`` from async code.
    """
    try:
        sock, raw = _open_socket()
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendto(build_echo_request(os.getpid(), seq), (host, 0))
        t0 = time.monotonic()
        deadline = t0 + timeout
        # Loop until our reply arrives or the deadline passes — a shared host can
        # deliver an unrelated ICMP message first; we want the echo reply.
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            packet, _ = sock.recvfrom(1024)
            if icmp_type(packet, raw=raw) == _ICMP_ECHO_REPLY:
                return (time.monotonic() - t0) * 1000
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()
