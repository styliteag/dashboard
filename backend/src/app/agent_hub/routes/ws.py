"""Agent WebSocket endpoint + GUI-proxy tunnel WS (no session auth on /ws/agent)."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

import asyncssh
import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.roles import WRITE_ROLES
from app.config import get_settings
from app.connectivity import service as conn_service
from app.crypto.secrets import decrypt
from app.db.base import get_sessionmaker
from app.db.models import Instance, User
from app.devices.types import DeviceType, Transport
from app.instances.service import get_instance
from app.ipsec import ping_service
from app.net import client_ip
from app.securepoint.ssh import SecurepointSSHError, SSHConfig, open_interactive

log = structlog.get_logger("app.agent_hub.routes")

router = APIRouter(tags=["agent"])

# The two firewall kinds the agent's detect_platform() can report. Only these
# may self-heal below — other device types must never flip on an agent's word.
_AGENT_PLATFORMS = {DeviceType.OPNSENSE.value, DeviceType.PFSENSE.value}


async def _sync_device_type(instance_id: int, platform: str) -> None:
    """Self-heal a misconfigured device kind from the agent's platform detection.

    Instances default to OPNsense on creation, so a pfSense (Plus) box enrolled
    without correcting the type dropdown is stored wrong — mislabeling the UI
    and building OPNsense deep links to pfSense pages. The agent runs on the
    box and knows better; trust it, but only within the opnsense↔pfsense pair.
    Best-effort: a failure here must never tear down the agent connection.
    """
    if platform not in _AGENT_PLATFORMS:
        return
    try:
        async with get_sessionmaker()() as session:
            inst = await session.get(Instance, instance_id)
            if inst is None or inst.device_type not in _AGENT_PLATFORMS:
                return
            if inst.device_type == platform:
                return
            log.info(
                "agent.device_type_corrected",
                instance_id=instance_id,
                old=inst.device_type,
                new=platform,
            )
            inst.device_type = platform
            await session.commit()
    except Exception:
        log.warning("agent.device_type_sync_failed", instance_id=instance_id)


# --- WebSocket endpoint (no session auth — uses agent_token) -----------------


@router.websocket("/ws/agent")
async def agent_websocket(ws: WebSocket):
    """WebSocket endpoint for agents. Auth via Bearer token in header."""
    await ws.accept()

    # Authenticate
    auth = ws.headers.get("authorization", "")
    token = auth.replace("Bearer ", "").strip() if auth.startswith("Bearer") else ""

    if not token:
        await ws.send_json({"type": "error", "message": "missing token"})
        await ws.close(code=4001)
        return

    # Look up instance by token
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        inst = (
            await session.execute(
                select(Instance).where(
                    Instance.agent_token == token,
                    Instance.transport == Transport.PUSH.value,
                    Instance.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()

    if inst is None:
        await ws.send_json({"type": "error", "message": "invalid token"})
        await ws.close(code=4003)
        return

    instance_id = inst.id
    instance_name = inst.name
    # Effective push cadence to mirror to the agent (per-instance override or default).
    push_interval = (
        getattr(inst, "push_interval_seconds", None) or get_settings().push_interval_seconds
    )

    agent = await hub.register(ws, instance_id, instance_name)

    try:
        # Wait for hello
        raw = await ws.receive_text()
        hello = json.loads(raw)
        if hello.get("type") == "hello":
            agent.agent_version = hello.get("agent_version", "")
            agent.platform = hello.get("platform", "")
            await _sync_device_type(instance_id, agent.platform)
            await ws.send_json(
                {
                    "type": "welcome",
                    "instance_id": instance_id,
                    "instance_name": instance_name,
                    "push_interval": push_interval,
                }
            )
            # Push the instance's IPsec ping-monitor + standalone connectivity
            # config so the agent starts probing immediately on (re)connect. The
            # agent's monitor sets start empty and are only populated by a
            # config_update, so without this re-push a reconnect (e.g. after a
            # backend restart) leaves connectivity monitors unprobed ("no data
            # yet"). Best-effort: a failure here must never tear down the agent
            # connection.
            try:
                async with get_sessionmaker()() as cfg_session:
                    await ping_service.push_to_agent(cfg_session, instance_id)
                    await conn_service.push_to_agent(cfg_session, instance_id)
            except Exception:
                log.warning("agent.ping_config_push_failed", instance_id=instance_id)

        # Main message loop
        async for raw in ws.iter_text():
            try:
                msg = json.loads(raw)
                msg_type = msg.get("type", "")

                if msg_type == "metrics":
                    await hub.handle_metrics(instance_id, msg.get("data", {}))

                elif msg_type == "command_result":
                    agent.resolve_command(
                        msg.get("request_id", ""),
                        msg.get("result", {}),
                    )

                elif msg_type == "tunnel":
                    # GUI-proxy bytes from the firewall → route to the client handler.
                    hub.deliver_tunnel(msg.get("stream", ""), msg)

                elif msg_type == "pong":
                    pass

            except json.JSONDecodeError:
                pass
            except Exception:
                # A single bad message (e.g. a converter/DB error on one push)
                # must NOT disconnect the agent — log it and keep the connection.
                log.exception("agent.message_error", instance_id=instance_id, msg_type=msg_type)

    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("agent.ws_error", instance_id=instance_id)
    finally:
        # Identity-aware: only this connection unregisters itself, so a stale old
        # connection's teardown cannot evict a freshly-registered reconnect.
        hub.unregister(instance_id, agent)


# --- GUI proxy: raw TCP tunnel over the agent WS (see §18) -------------------


async def _tunnel_client_to_agent(client_ws: WebSocket, agent, stream: str) -> None:
    """Forward raw bytes from the local client to the firewall via the agent."""
    async for data in client_ws.iter_bytes():
        await agent.ws.send_json(
            {
                "type": "tunnel",
                "op": "data",
                "stream": stream,
                "data": base64.b64encode(data).decode(),
            }
        )


async def _tunnel_agent_to_client(client_ws: WebSocket, queue: asyncio.Queue) -> None:
    """Forward firewall bytes (delivered onto the queue) back to the local client."""
    while True:
        frame = await queue.get()
        if frame.get("op") == "close":
            return
        if frame.get("op") == "data":
            await client_ws.send_bytes(base64.b64decode(frame.get("data", "")))


# --- Shared WebSocket authorization (GUI tunnel + shell) ---------------------


def _ws_origin_ok(ws: WebSocket) -> bool:
    """Reject a cross-site WS handshake. A SameSite=Lax cookie is still sent on a
    same-site request, and the product serves firewall-controlled content on
    same-eTLD+1 gui-proxy subdomains — so a strict Origin allowlist is what stops
    JS on a compromised firewall WebUI from driving these sockets. Non-browser
    clients (no Origin) pass; localhost/127.0.0.1 always pass (dev)."""
    origin = ws.headers.get("origin")
    if not origin:
        return True
    host = (urlsplit(origin).hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    s = get_settings()
    allowed = {(urlsplit(s.webauthn_origin).hostname or "").lower()}
    allowed.update(h.strip().lower() for h in s.ws_allowed_origin_hosts.split(",") if h.strip())
    allowed.discard("")
    return host in allowed


async def _ws_authenticate(ws: WebSocket, session, *, write: bool) -> User | None:
    """Full session validation for a WS route, parity with REST ``current_user``:
    Origin, presence of user_id/password_version, a passed second factor, the user
    still existing + password_version match + not disabled, and (when ``write``)
    a non-``view_only`` role. Closes the socket and returns None on any failure."""
    if not _ws_origin_ok(ws):
        await ws.close(code=4403)
        return None
    user_id = ws.session.get("user_id")
    pwv = ws.session.get("password_version")
    if not user_id or pwv is None or ws.session.get("mfa_passed") is not True:
        await ws.close(code=4401)
        return None
    user = await session.get(User, user_id)
    # Unlike current_user we don't clear the session here (no Response on a WS); the
    # stale cookie simply fails again on the next attempt.
    if user is None or user.password_version != pwv or user.disabled:
        await ws.close(code=4401)
        return None
    if write and user.role not in WRITE_ROLES:
        await ws.close(code=4403)
        return None
    return user


@router.websocket("/ws/tunnel/{instance_id}")
async def tunnel_websocket(ws: WebSocket, instance_id: int):
    """Bridge a local client socket to the firewall's GUI port through the agent.

    The client (a local port-forwarder) sends/receives raw TCP bytes as binary WS
    frames; we multiplex them as `tunnel` frames over the agent's WS. The browser
    speaks TLS end-to-end with the firewall, so no HTML rewriting is needed.
    """
    await ws.accept()
    async with get_sessionmaker()() as session:
        # A GUI/TCP bridge to the box is a write-level action (mirrors POST
        # /gui/open, which is require_write) — enforce role + full session validity.
        user = await _ws_authenticate(ws, session, write=True)
        if user is None:
            return
        # Group scoping: tunnelling to a foreign-group firewall is a full GUI/TCP
        # bridge — enforce instance visibility, not just authentication.
        inst = await get_instance(session, instance_id, user)
    if inst is None:
        await ws.close(code=4403)
        return
    agent = hub.get(instance_id)
    if agent is None:
        await ws.close(code=4404)
        return

    stream = uuid.uuid4().hex
    queue = hub.open_tunnel(stream)
    try:
        await agent.ws.send_json({"type": "tunnel", "op": "open", "stream": stream})
        pumps = [
            asyncio.create_task(_tunnel_client_to_agent(ws, agent, stream)),
            asyncio.create_task(_tunnel_agent_to_client(ws, queue)),
        ]
        _, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("tunnel.error", instance_id=instance_id, stream=stream)
    finally:
        hub.close_tunnel(stream)
        with contextlib.suppress(Exception):
            await agent.ws.send_json({"type": "tunnel", "op": "close", "stream": stream})
        with contextlib.suppress(Exception):
            await ws.close()


# --- Interactive shell: browser terminal to a root PTY (SPIKE, see §22) -------

# Server→client keepalive cadence. An idle terminal (no keystrokes) would
# otherwise be cut by Traefik / an intermediate proxy's idle timeout; a periodic
# frame keeps the socket warm. Server-side so a backgrounded browser tab (whose
# timers get throttled) still stays connected. Under the common 60s proxy floor.
_SHELL_PING_INTERVAL = 25
# An idle root shell is torn down after this many seconds with no keystrokes, and
# every session is capped at an absolute lifetime regardless of activity.
_SHELL_IDLE_SECONDS = 900
_SHELL_MAX_LIFETIME = 8 * 3600
# Concurrency caps: bound forked root PTYs so one account can't fork-bomb a box.
_SHELL_MAX_PER_USER = 5
_SHELL_MAX_PER_INSTANCE = 5
# Forensic recording cap (bytes of box output per session), when recording is on.
_SHELL_RECORD_CAP = 8 * 1024 * 1024

_shell_count_user: dict[int, int] = {}
_shell_count_inst: dict[int, int] = {}


def _shell_slot_acquire(user_id: int, instance_id: int) -> bool:
    """Reserve a concurrency slot; False if the per-user or per-box cap is reached."""
    if (
        _shell_count_user.get(user_id, 0) >= _SHELL_MAX_PER_USER
        or _shell_count_inst.get(instance_id, 0) >= _SHELL_MAX_PER_INSTANCE
    ):
        return False
    _shell_count_user[user_id] = _shell_count_user.get(user_id, 0) + 1
    _shell_count_inst[instance_id] = _shell_count_inst.get(instance_id, 0) + 1
    return True


def _shell_slot_release(user_id: int, instance_id: int) -> None:
    for counts, key in ((_shell_count_user, user_id), (_shell_count_inst, instance_id)):
        n = counts.get(key, 0) - 1
        if n > 0:
            counts[key] = n
        else:
            counts.pop(key, None)


class _ShellRecorder:
    """Append the box's terminal output to a capped file for forensics. Best-effort:
    any IO error silently stops recording rather than breaking the session."""

    def __init__(self, path: str):
        self._n = 0
        try:
            self._f = open(path, "ab")  # noqa: SIM115 — long-lived; closed in close()
        except OSError:
            self._f = None

    def out(self, data: bytes) -> None:
        if self._f is None or self._n >= _SHELL_RECORD_CAP:
            return
        with contextlib.suppress(OSError):
            self._f.write(data)
            self._f.flush()
            self._n += len(data)

    def close(self) -> None:
        if self._f is not None:
            with contextlib.suppress(OSError):
                self._f.close()
            self._f = None


def _open_recorder(stream: str, instance_id: int, user_id: int) -> _ShellRecorder | None:
    """A recorder when ``shell_record_dir`` is set, else None (recording off)."""
    d = get_settings().shell_record_dir
    if not d:
        return None
    with contextlib.suppress(OSError):
        os.makedirs(d, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return _ShellRecorder(os.path.join(d, f"{ts}-inst{instance_id}-user{user_id}-{stream}.log"))


async def _shell_watchdog(state: dict) -> None:
    """Complete (→ session teardown) once idle-timeout or max-lifetime is exceeded."""
    loop = asyncio.get_event_loop()
    start = loop.time()
    while True:
        await asyncio.sleep(30)
        now = loop.time()
        if now - state["last"] > _SHELL_IDLE_SECONDS or now - start > _SHELL_MAX_LIFETIME:
            return


async def _shell_agent_to_client(client_ws: WebSocket, queue: asyncio.Queue, rec) -> None:
    """Forward box output to the terminal, teeing it to the recorder when present."""
    while True:
        frame = await queue.get()
        if frame.get("op") == "close":
            return
        if frame.get("op") == "data":
            raw = base64.b64decode(frame.get("data", ""))
            if rec is not None:
                rec.out(raw)
            await client_ws.send_bytes(raw)


async def _shell_keepalive(client_ws: WebSocket) -> None:
    """Emit a periodic keepalive frame so idle sessions survive proxy timeouts."""
    try:
        while True:
            await asyncio.sleep(_SHELL_PING_INTERVAL)
            await client_ws.send_json({"type": "ping"})
    except (WebSocketDisconnect, RuntimeError):
        return


async def _shell_client_to_agent(client_ws: WebSocket, agent, stream: str, state: dict) -> None:
    """Forward keystrokes (binary) and resize control (JSON text) to the agent PTY.

    Updates ``state["last"]`` on every client frame so the idle watchdog can tell a
    live session from an abandoned one. Exits cleanly on client disconnect OR on a
    failed agent send — the latter happens when the agent WS drops mid-session
    (e.g. agent restart/self-update): without the guard the raw ``RuntimeError``
    surfaces as an unretrieved task exception. The outer handler then tears down.
    """
    loop = asyncio.get_event_loop()
    try:
        while True:
            msg = await client_ws.receive()
            if msg["type"] == "websocket.disconnect":
                return
            data = msg.get("bytes")
            if data is not None:
                # Only real keystrokes count as activity — a keepalive pong must
                # not reset the idle timer, or an abandoned shell never times out.
                state["last"] = loop.time()
                await agent.ws.send_json(
                    {
                        "type": "tunnel",
                        "op": "data",
                        "stream": stream,
                        "data": base64.b64encode(data).decode(),
                    }
                )
                continue
            text = msg.get("text")
            if text is not None:
                with contextlib.suppress(Exception):
                    ctrl = json.loads(text)
                    if ctrl.get("type") == "resize":
                        await agent.ws.send_json(
                            {
                                "type": "tunnel",
                                "op": "resize",
                                "stream": stream,
                                "rows": int(ctrl.get("rows") or 0),
                                "cols": int(ctrl.get("cols") or 0),
                            }
                        )
    except (WebSocketDisconnect, RuntimeError):
        return


async def _ssh_proc_to_client(ws: WebSocket, proc, rec) -> None:
    """Forward the box's PTY output (over SSH) to the terminal, teeing to recorder."""
    try:
        while True:
            data = await proc.stdout.read(65536)
            if not data:  # EOF — the shell exited
                return
            if rec is not None:
                rec.out(data)
            await ws.send_bytes(data)
    except (asyncssh.Error, WebSocketDisconnect, RuntimeError, ConnectionError):
        return


async def _ssh_client_to_proc(ws: WebSocket, proc, state: dict) -> None:
    """Forward keystrokes (binary) and resize control (JSON text) to the SSH PTY.

    Updates ``state["last"]`` on keystrokes (not pong/resize) for the idle watchdog.
    """
    loop = asyncio.get_event_loop()
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                return
            data = msg.get("bytes")
            if data is not None:
                state["last"] = loop.time()
                proc.stdin.write(data)
                with contextlib.suppress(Exception):
                    await proc.stdin.drain()
                continue
            text = msg.get("text")
            if text is not None:
                with contextlib.suppress(Exception):
                    ctrl = json.loads(text)
                    if ctrl.get("type") == "resize":
                        proc.change_terminal_size(
                            int(ctrl.get("cols") or 0) or 80, int(ctrl.get("rows") or 0) or 24
                        )
    except (WebSocketDisconnect, RuntimeError, asyncssh.Error, ConnectionError):
        return


async def _run_agent_shell(ws: WebSocket, agent, stream: str, rec, state: dict) -> None:
    """Shell backend for agent-mode boxes: the agent forks the PTY, we multiplex
    `tunnel` frames over its WebSocket (same path as the GUI proxy)."""
    queue = hub.open_tunnel(stream)
    try:
        await agent.ws.send_json(
            {
                "type": "tunnel",
                "op": "open",
                "stream": stream,
                "kind": "shell",
                "rows": 24,
                "cols": 80,
            }
        )
        pumps = [
            asyncio.create_task(_shell_keepalive(ws)),
            asyncio.create_task(_shell_client_to_agent(ws, agent, stream, state)),
            asyncio.create_task(_shell_agent_to_client(ws, queue, rec)),
            asyncio.create_task(_shell_watchdog(state)),
        ]
        _, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    finally:
        hub.close_tunnel(stream)
        with contextlib.suppress(Exception):
            await agent.ws.send_json({"type": "tunnel", "op": "close", "stream": stream})


async def _run_ssh_shell(ws: WebSocket, cfg: SSHConfig, rec, state: dict) -> None:
    """Shell backend for agent-less boxes (Securepoint): the BACKEND opens a
    host-key-verified SSH PTY to the box and bridges it. Closes the SSH channel on
    teardown so no root shell lingers on the box."""
    try:
        conn, proc = await open_interactive(cfg, rows=24, cols=80)
    except SecurepointSSHError as exc:
        with contextlib.suppress(Exception):
            await ws.send_bytes(f"\r\n\x1b[31mSSH connection failed: {exc}\x1b[0m\r\n".encode())
        return
    try:
        pumps = [
            asyncio.create_task(_shell_keepalive(ws)),
            asyncio.create_task(_ssh_client_to_proc(ws, proc, state)),
            asyncio.create_task(_ssh_proc_to_client(ws, proc, rec)),
            asyncio.create_task(_shell_watchdog(state)),
        ]
        _, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    finally:
        with contextlib.suppress(Exception):
            proc.close()
        with contextlib.suppress(Exception):
            conn.close()
            await conn.wait_closed()


@router.websocket("/ws/shell/{instance_id}")
async def shell_websocket(ws: WebSocket, instance_id: int):
    """Bridge an xterm.js terminal to a root shell on the box.

    Two transports, same WS: an **agent** box forks the PTY and multiplexes it over
    its WebSocket; an agent-less **Securepoint** box (SSH-enriched, host key pinned)
    gets a PTY that the backend opens over asyncssh. ARBITRARY ROOT RCE — gated by
    ``settings.shell_enabled`` + per-instance ``shell_enabled`` + a write role, full
    session validation and a pinned host key (SSH). Open/close are audited.
    """
    await ws.accept()
    # Feature gate first — never even hint the capability exists when disabled.
    if not get_settings().shell_enabled:
        await ws.close(code=4403)
        return
    # Same trusted-hops logic as REST audit (spoof-safe behind Traefik); WebSocket
    # is HTTPConnection-shaped, so client_ip's .headers/.client access applies.
    source_ip = client_ip(ws)
    async with get_sessionmaker()() as session:
        # A root shell is the most privileged action in the product — require a
        # write role + full session validity + a passed second factor, not mere
        # visibility. (Origin, disabled, MFA all enforced in _ws_authenticate.)
        user = await _ws_authenticate(ws, session, write=True)
        if user is None:
            return
        # Group scoping: a shell is a full root bridge — enforce instance
        # visibility, not just authentication.
        inst = await get_instance(session, instance_id, user)
    if inst is None:
        await ws.close(code=4403)
        return
    # Per-instance opt-in on top of the global gate: the box must have the terminal
    # explicitly enabled (Edit instance → "Terminal (root shell)").
    if not inst.shell_enabled:
        await ws.close(code=4403)
        return
    # Transport: a connected agent, else a Securepoint box reachable over a pinned
    # SSH key. Neither → nothing to attach to.
    agent = hub.get(instance_id)
    ssh_ready = (
        inst.device_type == DeviceType.SECUREPOINT.value
        and inst.ssh_enabled
        and inst.ssh_key_enc is not None
        and inst.ssh_host_key is not None
    )
    if agent is None and not ssh_ready:
        await ws.close(code=4404)
        return
    if not _shell_slot_acquire(user.id, instance_id):
        log.warning("shell.rejected_cap", instance_id=instance_id, user_id=user.id)
        await ws.close(code=4008)  # policy/limit
        return

    stream = uuid.uuid4().hex
    async with get_sessionmaker()() as session:
        await write_audit(
            session,
            action="shell.open",
            result="ok",
            user_id=user.id,
            target_type="instance",
            target_id=instance_id,
            source_ip=source_ip,
            detail={"stream": stream, "transport": "agent" if agent else "ssh"},
        )
        await session.commit()
    log.info(
        "shell.open",
        instance_id=instance_id,
        user_id=user.id,
        stream=stream,
        ip=source_ip,
        transport="agent" if agent else "ssh",
    )
    rec = _open_recorder(stream, instance_id, user.id)
    state = {"last": asyncio.get_event_loop().time()}
    try:
        if agent is not None:
            await _run_agent_shell(ws, agent, stream, rec, state)
        else:
            cfg = SSHConfig(
                host=inst.ssh_host,
                port=inst.ssh_port,
                user=inst.ssh_user,
                private_key=decrypt(inst.ssh_key_enc),
                host_key=inst.ssh_host_key,
            )
            await _run_ssh_shell(ws, cfg, rec, state)
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("shell.error", instance_id=instance_id, stream=stream)
    finally:
        _shell_slot_release(user.id, instance_id)
        if rec is not None:
            rec.close()
        with contextlib.suppress(Exception):
            await ws.close()
        with contextlib.suppress(Exception):
            async with get_sessionmaker()() as session:
                await write_audit(
                    session,
                    action="shell.close",
                    result="ok",
                    user_id=user.id,
                    target_type="instance",
                    target_id=instance_id,
                    source_ip=source_ip,
                    detail={"stream": stream},
                )
                await session.commit()
