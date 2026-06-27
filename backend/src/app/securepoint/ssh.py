"""SSH transport for Securepoint: run ``swanctl --raw`` on the box and parse it.

The dashboard authenticates with a single ed25519 key (``DASH_SSH_PRIVATE_KEY``);
its public half is installed on each box (see docs/securepoint-ssh.md). This is
what gives the pull path the IKE cookies + ESP SPIs + byte counters that the
spcgi API never exposes — i.e. the data needed to pair tunnel ends across NAT.

Host-key handling is trust-on-first-use: a configured ``host_key`` is verified
fail-closed before any command runs; ``probe_host_key`` captures it for storage.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import asyncssh

from app.securepoint.swanctl import ipsec_status_from_swanctl
from app.xsense.schemas import IPsecServiceStatus

# Budget: the global VPN overview wraps ipsec_status() in a wait_for(_FETCH_TIMEOUT)
# (views/routes.py, 8s) and silently drops the instance on timeout. Keep the whole
# SSH round-trip under that: connect + the two swanctl runs (executed concurrently).
_CONNECT_TIMEOUT = 4.0
_CMD_TIMEOUT = 3.0


class SecurepointSSHError(RuntimeError):
    pass


@dataclass(frozen=True)
class SSHConfig:
    """Per-instance SSH access for swanctl enrichment (private key already decrypted)."""

    host: str
    port: int
    user: str
    private_key: str
    host_key: str | None = None


def _key_blob(openssh_line: str) -> str:
    """The base64 blob of an ``ssh-ed25519 AAAA... [comment]`` line (identity part)."""
    parts = openssh_line.split()
    return parts[1] if len(parts) >= 2 else openssh_line.strip()


async def _connect(
    host: str,
    port: int,
    user: str,
    private_key_pem: str,
    host_key: str | None,
) -> tuple[asyncssh.SSHClientConnection, str]:
    """Open a connection; return (conn, server_host_key_openssh). Verifies the
    pinned host key fail-closed when one is given."""
    if not private_key_pem.strip():
        raise SecurepointSSHError("no SSH private key configured (DASH_SSH_PRIVATE_KEY)")
    try:
        client_key = asyncssh.import_private_key(private_key_pem)
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise SecurepointSSHError(f"bad SSH private key: {exc}") from exc

    try:
        # known_hosts=None: skip asyncssh's lookup; we verify the host key ourselves
        # right after the handshake and before running any command.
        conn = await asyncio.wait_for(
            asyncssh.connect(
                host,
                port=port,
                username=user,
                client_keys=[client_key],
                known_hosts=None,
            ),
            timeout=_CONNECT_TIMEOUT,
        )
    except (TimeoutError, OSError, asyncssh.Error) as exc:
        raise SecurepointSSHError(f"SSH connect {user}@{host}:{port} failed: {exc}") from exc

    server_key = conn.get_server_host_key()
    server_line = server_key.export_public_key().decode().strip() if server_key else ""
    if host_key and _key_blob(server_line) != _key_blob(host_key):
        conn.close()
        await conn.wait_closed()
        raise SecurepointSSHError("SSH host key mismatch (possible MITM) — refused")
    return conn, server_line


async def probe_host_key(host: str, port: int, user: str, private_key_pem: str) -> str:
    """Connect once (unpinned) and return the box's host key for storage (TOFU)."""
    conn, server_line = await _connect(host, port, user, private_key_pem, host_key=None)
    conn.close()
    await conn.wait_closed()
    return server_line


async def fetch_ipsec_status(
    host: str,
    port: int,
    user: str,
    private_key_pem: str,
    host_key: str | None,
    *,
    running: bool,
) -> IPsecServiceStatus:
    """Run swanctl over SSH and parse it into the shared IPsec DTO (with SPIs)."""
    conn, _ = await _connect(host, port, user, private_key_pem, host_key)
    try:
        sas = await asyncio.wait_for(conn.run("swanctl --list-sas --raw"), timeout=_CMD_TIMEOUT)
        conns = await asyncio.wait_for(conn.run("swanctl --list-conns --raw"), timeout=_CMD_TIMEOUT)
    except (TimeoutError, asyncssh.Error) as exc:
        raise SecurepointSSHError(f"swanctl over SSH failed: {exc}") from exc
    finally:
        conn.close()
        await conn.wait_closed()
    return ipsec_status_from_swanctl(
        str(sas.stdout or ""), str(conns.stdout or ""), running=running
    )
