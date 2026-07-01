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
from app.config import get_settings
from app.connectivity import service as conn_service
from app.db.base import get_sessionmaker
from app.db.models import Instance, User
from app.devices.types import Transport
from app.ipsec import ping_service

log = structlog.get_logger("app.agent_hub.routes")

router = APIRouter(tags=["agent"])


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
        # Unlike current_user we don't clear the session here (no Response on a WS);
        # the stale cookie simply fails this check again on the next attempt.
        await ws.close(code=4401)
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
