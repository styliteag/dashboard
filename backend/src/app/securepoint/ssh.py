"""SSH transport for Securepoint: run ``swanctl --raw`` on the box and parse it.

The dashboard authenticates with a single ed25519 key (``DASH_SSH_PRIVATE_KEY``);
its public half is installed on each box (see docs/securepoint-ssh.md). This is
what gives the pull path the IKE cookies + ESP SPIs + byte counters that the
spcgi API never exposes — i.e. the data needed to pair tunnel ends across NAT.

Host-key handling is trust-on-first-use, fail-closed: command-running connections
refuse to proceed unless a pinned ``host_key`` is present and matches the server;
``probe_host_key`` is the only path that connects unpinned, to capture it for
storage. Until a key is pinned, callers fall back to the spcgi API.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

import asyncssh

from app.securepoint.swanctl import ipsec_status_from_swanctl
from app.xsense.schemas import DiagnosisSection, IPsecServiceStatus

# Diagnose runs several commands + a ping + a syslog dump; it's a user-triggered
# one-off (no wait_for around it), so a generous timeout is fine.
_DIAG_TIMEOUT = 25.0
_SEC = "@@SEC@@"
# Connection names are safe shell tokens; reject anything else before interpolating.
_SAFE_NAME = re.compile(r"[A-Za-z0-9._:-]{1,128}")

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
    *,
    require_host_key: bool = True,
) -> tuple[asyncssh.SSHClientConnection, str]:
    """Open a connection; return (conn, server_host_key_openssh).

    Fail-closed on the host key: a command-running connection (``require_host_key``,
    the default) refuses to proceed unless a pinned ``host_key`` is supplied and
    matches the server. Only ``probe_host_key`` connects unpinned (TOFU capture), by
    passing ``require_host_key=False``. Without this, ``known_hosts=None`` would
    accept any host key, letting an on-path attacker impersonate the box and feed
    fabricated swanctl/diagnostic output.
    """
    if require_host_key and not host_key:
        raise SecurepointSSHError(
            "SSH host key not pinned — refusing to connect unverified "
            "(enrichment falls back to the spcgi API until the key is captured)"
        )
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
    conn, server_line = await _connect(
        host, port, user, private_key_pem, host_key=None, require_host_key=False
    )
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


def _diag_script(name: str) -> str:
    """Shell run over one SSH session that emits ``@@SEC@@<title>``-delimited blocks.

    Gathers as much as the box exposes: the connection config, live SAs, installed
    policies, the recent charon log (vici-poll noise stripped — failure lines like
    NO_PROPOSAL_CHOSEN / AUTHENTICATION_FAILED / 'giving up' live here regardless of
    whether they carry the conn name), and a one-shot peer-reachability ping.
    """
    return (
        f"N='{name}'\n"
        f"echo '{_SEC}Connection config (swanctl --list-conns)'\n"
        "swanctl --list-conns 2>&1\n"
        f"echo '{_SEC}Live IKE / CHILD SAs (swanctl --list-sas)'\n"
        'swanctl --list-sas --ike "$N" 2>&1\n'
        f"echo '{_SEC}Recent IPsec log (charon)'\n"
        # syslog is a padded `msgid|date|app|pid|msg` table — match the app field
        # (col 3) robustly, drop our own vici-poll noise, cap the tail.
        "(echo 'syslog get' | spcli 2>/dev/null) "
        "| awk -F'|' 'NR>2 && $3 ~ /charon/ && $0 !~ /\\[CFG\\] vici client/' "
        "| tail -n 300\n"
        f"echo '{_SEC}Peer reachability'\n"
        "REMOTE=$(swanctl --list-conns --raw 2>/dev/null | grep -oE 'remote_addrs=\\[[^]]*' "
        "| grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | head -n1)\n"
        '[ -z "$REMOTE" ] && REMOTE=$(swanctl --list-sas --ike "$N" --raw 2>/dev/null '
        "| grep -oE 'remote-host=[0-9.]+' | head -n1 | cut -d= -f2)\n"
        '[ -n "$REMOTE" ] && { echo "ping $REMOTE:"; ping -c 2 -w 4 "$REMOTE" 2>&1; } '
        '|| echo "no concrete peer IP (remote=%any / responder-only) — nothing to ping"\n'
    )


def _parse_sections(out: str) -> list[DiagnosisSection]:
    sections: list[DiagnosisSection] = []
    title: str | None = None
    buf: list[str] = []
    for line in out.splitlines():
        if line.startswith(_SEC):
            if title is not None:
                sections.append(DiagnosisSection(title=title, content="\n".join(buf).strip()))
            title = line[len(_SEC) :].strip()
            buf = []
        elif title is not None:
            buf.append(line)
    if title is not None:
        sections.append(DiagnosisSection(title=title, content="\n".join(buf).strip()))
    return sections


async def fetch_diagnosis(
    host: str,
    port: int,
    user: str,
    private_key_pem: str,
    host_key: str | None,
    tunnel_id: str,
) -> list[DiagnosisSection]:
    """Gather a readable per-tunnel diagnostic bundle over one SSH session."""
    if not _SAFE_NAME.fullmatch(tunnel_id):
        raise SecurepointSSHError(f"unsafe tunnel id: {tunnel_id!r}")
    conn, _ = await _connect(host, port, user, private_key_pem, host_key)
    try:
        res = await asyncio.wait_for(conn.run(_diag_script(tunnel_id)), timeout=_DIAG_TIMEOUT)
    except (TimeoutError, asyncssh.Error) as exc:
        raise SecurepointSSHError(f"diagnose over SSH failed: {exc}") from exc
    finally:
        conn.close()
        await conn.wait_closed()
    return _parse_sections(str(res.stdout or ""))
