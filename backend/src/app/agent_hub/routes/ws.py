"""Agent WebSocket endpoint + GUI-proxy tunnel WS (no session auth on /ws/agent)."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import uuid

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.config import get_settings
from app.connectivity import service as conn_service
from app.db.base import get_sessionmaker
from app.db.models import Instance, User
from app.devices.types import DeviceType, Transport
from app.instances.service import get_instance
from app.ipsec import ping_service
from app.net import client_ip

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


@router.websocket("/ws/tunnel/{instance_id}")
async def tunnel_websocket(ws: WebSocket, instance_id: int):
    """Bridge a local client socket to the firewall's GUI port through the agent.

    The client (a local port-forwarder) sends/receives raw TCP bytes as binary WS
    frames; we multiplex them as `tunnel` frames over the agent's WS. The browser
    speaks TLS end-to-end with the firewall, so no HTML rewriting is needed.
    """
    await ws.accept()
    # Full session validation (not just presence of user_id): the user must still
    # exist and the password_version must match, so a cookie invalidated by a
    # password change can't open a tunnel within its remaining lifetime. F5.
    user_id = ws.session.get("user_id")
    pwv = ws.session.get("password_version")
    if not user_id or pwv is None:
        await ws.close(code=4401)
        return
    async with get_sessionmaker()() as session:
        user = await session.get(User, user_id)
        if user is None or user.password_version != pwv:
            # Unlike current_user we don't clear the session here (no Response on a
            # WS); the stale cookie simply fails this check again on the next attempt.
            await ws.close(code=4401)
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


async def _shell_keepalive(client_ws: WebSocket) -> None:
    """Emit a periodic keepalive frame so idle sessions survive proxy timeouts."""
    try:
        while True:
            await asyncio.sleep(_SHELL_PING_INTERVAL)
            await client_ws.send_json({"type": "ping"})
    except (WebSocketDisconnect, RuntimeError):
        return


async def _shell_client_to_agent(client_ws: WebSocket, agent, stream: str) -> None:
    """Forward keystrokes (binary) and resize control (JSON text) to the agent PTY.

    Exits cleanly on client disconnect OR on a failed agent send — the latter
    happens when the agent WS drops mid-session (e.g. agent restart/self-update):
    without the guard the raw ``RuntimeError`` surfaces as an unretrieved task
    exception. The outer handler then tears the shell down normally.
    """
    try:
        while True:
            msg = await client_ws.receive()
            if msg["type"] == "websocket.disconnect":
                return
            data = msg.get("bytes")
            if data is not None:
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


@router.websocket("/ws/shell/{instance_id}")
async def shell_websocket(ws: WebSocket, instance_id: int):
    """Bridge an xterm.js terminal to a root shell on the firewall via the agent.

    The agent forks a login PTY and streams its output back as `tunnel` data
    frames (same multiplex as the GUI proxy). ARBITRARY ROOT RCE on the box —
    gated by ``settings.shell_enabled`` (off by default) and, like the GUI tunnel,
    full session validation plus group-scoped instance visibility. Every open and
    close is audited with the acting user and source IP.
    """
    await ws.accept()
    # Feature gate first — never even hint the capability exists when disabled.
    if not get_settings().shell_enabled:
        await ws.close(code=4403)
        return
    # Full session validation (mirrors tunnel_websocket): the user must still exist
    # and password_version match, so a cookie invalidated by a password change
    # cannot open a root shell within its remaining lifetime.
    user_id = ws.session.get("user_id")
    pwv = ws.session.get("password_version")
    if not user_id or pwv is None:
        await ws.close(code=4401)
        return
    # Same trusted-hops logic as REST audit (spoof-safe behind Traefik); WebSocket
    # is HTTPConnection-shaped, so client_ip's .headers/.client access applies.
    source_ip = client_ip(ws)
    async with get_sessionmaker()() as session:
        user = await session.get(User, user_id)
        if user is None or user.password_version != pwv:
            await ws.close(code=4401)
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
    agent = hub.get(instance_id)
    if agent is None:
        await ws.close(code=4404)
        return

    stream = uuid.uuid4().hex
    async with get_sessionmaker()() as session:
        await write_audit(
            session,
            action="shell.open",
            result="ok",
            user_id=user_id,
            target_type="instance",
            target_id=instance_id,
            source_ip=source_ip,
        )
        await session.commit()
    log.info("shell.open", instance_id=instance_id, user_id=user_id, stream=stream, ip=source_ip)

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
            asyncio.create_task(_shell_client_to_agent(ws, agent, stream)),
            asyncio.create_task(_tunnel_agent_to_client(ws, queue)),
        ]
        _, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    except WebSocketDisconnect:
        pass
    except Exception:
        log.exception("shell.error", instance_id=instance_id, stream=stream)
    finally:
        hub.close_tunnel(stream)
        with contextlib.suppress(Exception):
            await agent.ws.send_json({"type": "tunnel", "op": "close", "stream": stream})
        with contextlib.suppress(Exception):
            await ws.close()
        with contextlib.suppress(Exception):
            async with get_sessionmaker()() as session:
                await write_audit(
                    session,
                    action="shell.close",
                    result="ok",
                    user_id=user_id,
                    target_type="instance",
                    target_id=instance_id,
                    source_ip=source_ip,
                )
                await session.commit()
