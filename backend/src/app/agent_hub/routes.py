"""Agent WebSocket endpoint + REST routes for agent management."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse, RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub import gui_caddy
from app.agent_hub.gui_auth import COOKIE_NAME, sign_gui_token, verify_gui_token
from app.agent_hub.gui_session import gui_sessions
from app.agent_hub.gui_tunnel import gui_tunnels
from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.auth.security import limiter
from app.config import get_settings
from app.connectivity import service as conn_service
from app.db.base import get_session, get_sessionmaker
from app.db.models import EnrollmentCode, Instance, User
from app.devices.types import Transport
from app.ipsec import ping_service
from app.net import client_ip

# Agent files are baked into /app/agent/ in the production container.
# Override via AGENT_DIR env var for local dev.
_AGENT_DIR = Path(os.environ.get("AGENT_DIR", "/app/agent"))

log = structlog.get_logger("app.agent_hub.routes")

router = APIRouter(tags=["agent"])


def _served_agent_version() -> str | None:
    """Parse __version__ from the agent script shipped in this container."""
    try:
        text = (_AGENT_DIR / "orbit_agent.py").read_text()
    except OSError:
        return None
    m = re.search(r"""^__version__\s*=\s*["']([^"']+)["']""", text, re.MULTILINE)
    return m.group(1) if m else None


def _agent_update_params() -> dict | None:
    """Build the agent.update command params, or None.

    Includes the offline-produced Ed25519 signature (orbit_agent.py.sig) when
    present — the dashboard only relays it, it never holds the signing key.
    """
    try:
        code = (_AGENT_DIR / "orbit_agent.py").read_bytes()
    except OSError:
        return None
    try:
        signature = (_AGENT_DIR / "orbit_agent.py.sig").read_text().strip()
    except OSError:
        signature = ""
    return {
        "version": _served_agent_version() or "unknown",
        "sha256": hashlib.sha256(code).hexdigest(),
        "code": base64.b64encode(code).decode(),
        "signature": signature,
    }


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


# --- REST: agent management --------------------------------------------------


class AgentTokenResponse(BaseModel):
    instance_id: int
    agent_token: str
    agent_mode: bool


class AgentStatusResponse(BaseModel):
    instance_id: int
    instance_name: str
    agent_mode: bool
    agent_connected: bool
    agent_last_seen: str | None
    agent_version: str | None = None  # reported by the connected agent
    served_version: str | None = None  # version shipped in this container
    update_available: bool = False
    gui_proxy_enabled: bool = False  # whether the GUI proxy is configured (global)
    gui_login_enabled: bool = False  # per-instance: replay a WebUI login on "Open GUI"
    platform: str | None = None  # "opnsense" / "pfsense", reported by the connected agent
    # Last self-update attempt the agent refused (e.g. signature/sha256), so the GUI
    # can show why it didn't update. None when the last attempt took (or none yet).
    last_update_error: str | None = None
    last_update_version: str | None = None


@router.post("/instances/{instance_id}/agent/enable", response_model=AgentTokenResponse)
async def enable_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> AgentTokenResponse:
    """Enable agent mode for an instance. Generates a unique token."""
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    token = secrets.token_urlsafe(48)
    inst.transport = Transport.PUSH.value
    inst.agent_token = token

    await write_audit(
        session,
        action="agent.enable",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return AgentTokenResponse(instance_id=instance_id, agent_token=token, agent_mode=True)


@router.post("/instances/{instance_id}/agent/disable")
async def disable_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Disable agent mode, revoke token, fall back to polling."""
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    inst.transport = Transport.DIRECT.value
    inst.agent_token = None

    # Disconnect if connected
    hub.unregister(instance_id)

    await write_audit(
        session,
        action="agent.disable",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return {"ok": True}


def _iso_utc(dt: datetime | None) -> str | None:
    """ISO-8601 with an explicit UTC offset.

    Timestamps are written as `datetime.now(timezone.utc)` but MariaDB DATETIME
    columns drop tzinfo, so the value reads back naive (still UTC wall-clock).
    Without an offset the browser parses the string as local time — e.g. a tunnel
    last seen at 08:22 CEST renders as 06:22. Tag naive values as UTC so the
    frontend can convert correctly.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


def _as_utc(dt: datetime) -> datetime:
    """Tag a naive MariaDB datetime as UTC so it can be compared to an aware now()."""
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


@router.get("/instances/{instance_id}/agent/status", response_model=AgentStatusResponse)
async def agent_status(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> AgentStatusResponse:
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    connected = hub.get(instance_id)
    agent_version = connected.agent_version if connected else None
    served = _served_agent_version()
    update_available = bool(agent_version and served and agent_version != served)

    return AgentStatusResponse(
        instance_id=instance_id,
        instance_name=inst.name,
        agent_mode=inst.agent_mode,
        agent_connected=hub.is_connected(instance_id),
        agent_last_seen=_iso_utc(inst.agent_last_seen),
        agent_version=agent_version,
        served_version=served,
        update_available=update_available,
        gui_proxy_enabled=get_settings().gui_proxy_enabled,
        gui_login_enabled=inst.gui_login_enabled,
        platform=connected.platform if connected else None,
        last_update_error=connected.last_update_error if connected else None,
        last_update_version=connected.last_update_version if connected else None,
    )


# Actions that return live credentials and must only run via their dedicated,
# purpose-built routes — never through this generic passthrough (which echoes the
# result to the caller and the audit log).
_INTERNAL_AGENT_ACTIONS = frozenset({"gui.login"})

# Result keys that may carry a live credential (firewall session cookie, API key,
# password) — masked before a command result is written to the audit log.
_SENSITIVE_RESULT_KEYS = frozenset({"cookies", "secret", "password", "key"})


def _redact_audit(result: dict) -> dict:
    """Copy a command result with credential-bearing keys masked for audit storage."""
    return {k: ("<redacted>" if k in _SENSITIVE_RESULT_KEYS else v) for k, v in result.items()}


@router.post("/instances/{instance_id}/agent/command")
async def send_agent_command(
    instance_id: int,
    body: dict,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Send a command to a connected agent."""
    action = body.get("action", "")
    params = body.get("params", {})
    if action in _INTERNAL_AGENT_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"action '{action}' is internal; use its dedicated endpoint",
        )

    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )

    result = await agent.send_command(action, params)

    await write_audit(
        session,
        action=f"agent.command.{action}",
        result="ok" if result.get("success") else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"action": action, "result": _redact_audit(result)},
    )
    await session.commit()
    return result


@router.post("/instances/{instance_id}/agent/update")
async def update_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Push the container's agent code to one connected agent (self-update).

    Per-instance by design: this is the canary mechanism (DR-6). Update one
    instance, confirm it reconnects healthy at the new version, then the next.
    """
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )

    params = _agent_update_params()
    if params is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="agent script not available"
        )

    # Pushing the served version to an agent already running it would only trip
    # the agent's anti-rollback ("pushed X not newer than X") and leave a sticky
    # "update rejected" marker — answer as a no-op instead.
    if agent.agent_version == params["version"]:
        return {
            "sent": False,
            "version": params["version"],
            "result": {"success": True, "output": f"already at {params['version']}"},
        }

    result = await agent.send_command("agent.update", params, timeout=30)

    # Persist a rejection on the connection so the reason stays visible in the GUI
    # (the agent stays connected when it refuses an update). A success restarts the
    # agent → fresh connection, which clears this.
    if result.get("success"):
        agent.last_update_error = None
        agent.last_update_version = None
    else:
        agent.last_update_error = result.get("output") or "update failed"
        agent.last_update_version = params["version"]

    await write_audit(
        session,
        action="agent.update",
        result="ok" if result.get("success") else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"version": params["version"], "result": result},
    )
    await session.commit()
    return {"sent": True, "version": params["version"], "result": result}


@router.get("/agents/connected")
async def list_connected_agents(
    _user: User = Depends(current_user),
) -> list[dict]:
    """List all currently connected agents, annotated with update availability."""
    served = _served_agent_version()
    return [
        {
            **a,
            "served_version": served,
            "update_available": bool(
                a["agent_version"] and served and a["agent_version"] != served
            ),
        }
        for a in hub.list_connected()
    ]


@router.post("/agents/update-all")
async def update_all_agents(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Push the container's agent code to every connected agent that is out of date.

    Up-to-date agents are skipped so they are not needlessly restarted.
    """
    params = _agent_update_params()
    if params is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="agent script not available"
        )
    served = params["version"]

    targets = [a for a in hub.list_connected() if a["agent_version"] != served]
    results = []
    for a in targets:
        agent = hub.get(a["instance_id"])
        if agent is None:
            continue
        # Re-check against the LIVE connection, not the snapshot above: an
        # overlapping update run may have already updated this box, and its
        # fresh reconnect reports the served version. Pushing anyway would trip
        # the agent's anti-rollback and pin a sticky "update rejected" marker.
        if agent.agent_version == served:
            continue
        result = await agent.send_command("agent.update", params, timeout=30)
        # Persist a rejection so it stays visible in the list (same as single update).
        if result.get("success"):
            agent.last_update_error = None
            agent.last_update_version = None
        else:
            agent.last_update_error = result.get("output") or "update failed"
            agent.last_update_version = served
        results.append(
            {
                "instance_id": a["instance_id"],
                "instance_name": a["instance_name"],
                "result": result,
            }
        )

    await write_audit(
        session,
        action="agent.update_all",
        result="ok",
        user_id=user.id,
        source_ip=client_ip(request),
        detail={"served_version": served, "count": len(results)},
    )
    await session.commit()
    return {"served_version": served, "updated": results}


# --- Local API relay ---------------------------------------------------------
# Tunnel an HTTP request to a NAT'd firewall's own REST API over the agent's
# WebSocket (see docs/agent-architecture.md §15). The dashboard holds NO firewall
# credentials — the agent injects them locally. Requires an admin session: the
# relay grants full API access, so the dashboard is the trust boundary.

# Request headers that are dashboard-local or hop-by-hop — never forward them
# (cookie/authorization are the *dashboard's* creds, not the firewall's).
_RELAY_DROP_REQUEST = frozenset(
    {
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "cookie",
        "authorization",
        "accept-encoding",
    }
)
# Response headers the agent already stripped; drop again so Starlette frames
# the body itself (length/encoding) rather than echoing the upstream values.
_RELAY_DROP_RESPONSE = frozenset(
    {
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "content-encoding",
    }
)


@router.post("/instances/{instance_id}/relay/enable")
async def enable_relay(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Enable the local API relay on a connected agent (idempotent).

    On pfSense this installs the community REST API package (needs internet egress
    on the firewall) and provisions the relay user; on OPNsense it just provisions.
    Explicit by design — never an automatic side-effect of first relay use.
    """
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )

    result = await agent.send_command("relay.enable", {}, timeout=200)

    await write_audit(
        session,
        action="agent.relay_enable",
        result="ok" if result.get("success") else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"result": result},
    )
    await session.commit()
    return {"sent": True, "result": result}


class RelayTestResponse(BaseModel):
    ok: bool
    status_code: int | None = None
    latency_ms: int | None = None
    error: str | None = None


# Declared BEFORE the catch-all relay proxy below so "relay/test" routes here
# and is not swallowed by the {path:path} matcher.
# Platform-specific, authenticated, lightweight GET endpoints — so the probe
# actually exercises the relay credentials (not just web-server reachability).
_RELAY_PROBE_PATHS = {
    "opnsense": "api/core/system/status",
    "pfsense": "api/v2/system/version",
}


@router.post("/instances/{instance_id}/relay/test", response_model=RelayTestResponse)
async def test_relay(instance_id: int, _user: User = Depends(require_write)) -> RelayTestResponse:
    """Make a real authenticated API call to the firewall through the agent relay.

    Picks a platform-appropriate API endpoint and reports whether it answered 2xx
    (relay + credentials work), plus round-trip latency. Runs server-side so a
    relayed 401/403 never reaches the browser — that would otherwise trip the
    auto-logout in the API wrapper.
    """
    agent = hub.get(instance_id)
    if agent is None:
        return RelayTestResponse(ok=False, error="agent not connected")

    platform = (getattr(agent, "platform", "") or "").lower()
    probe_path = _RELAY_PROBE_PATHS.get(platform, "")  # unknown → API-root reachability
    params = {
        "method": "GET",
        "path": probe_path,
        "headers": {},
        "body": base64.b64encode(b"").decode(),
    }
    t0 = time.monotonic()
    result = await agent.send_command("http.relay", params, timeout=15)
    latency_ms = int((time.monotonic() - t0) * 1000)

    # status 0 / no result = the request never reached the firewall (transport fail).
    status_code = int(result.get("status", 0)) if result else 0
    if status_code == 0:
        return RelayTestResponse(
            ok=False,
            latency_ms=latency_ms,
            error=(result.get("output", "relay failed") if result else "relay failed"),
        )
    ok = 200 <= status_code < 300
    error = None if ok else f"API returned HTTP {status_code}"
    return RelayTestResponse(ok=ok, status_code=status_code, latency_ms=latency_ms, error=error)


@router.api_route(
    "/instances/{instance_id}/relay/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def relay_to_agent(
    instance_id: int,
    path: str,
    request: Request,
    _user: User = Depends(require_write),
) -> Response:
    """Proxy ``{method} /relay/<path>`` to the firewall's local API via its agent."""
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )

    body = await request.body()
    rel_path = path + (f"?{request.url.query}" if request.url.query else "")
    params = {
        "method": request.method,
        "path": rel_path,
        "headers": {
            k: v for k, v in request.headers.items() if k.lower() not in _RELAY_DROP_REQUEST
        },
        "body": base64.b64encode(body).decode(),
    }

    result = await agent.send_command("http.relay", params, timeout=30)
    # status 0 (or a timed-out send_command with no status) = the request never
    # reached the firewall API → 502, distinct from a real upstream HTTP status.
    if not result or result.get("status", 0) == 0:
        detail = result.get("output", "relay failed") if result else "relay failed"
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)

    content = base64.b64decode(result.get("body") or "")
    headers = {
        k: v
        for k, v in (result.get("headers") or {}).items()
        if k.lower() not in _RELAY_DROP_RESPONSE
    }
    return Response(content=content, status_code=int(result["status"]), headers=headers)


# --- GUI proxy auth gate (token handoff + forward_auth, see §18) -------------


def _gui_base_url(inst: Instance) -> str:
    """The per-instance GUI origin: a prod ``{slug}`` subdomain, else the dev port.

    The template accepts ``{slug}`` (preferred, persistent) and ``{id}`` (legacy).
    """
    template = get_settings().gui_base_template
    if template:
        return template.format(slug=inst.slug, id=inst.id)
    return f"https://localhost:{9000 + inst.id}"  # dev convention (Caddy vhost)


class GuiOpenResponse(BaseModel):
    url: str


@router.post("/instances/{instance_id}/gui/open", response_model=GuiOpenResponse)
async def gui_open(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> GuiOpenResponse:
    """Mint a short-lived handoff URL that logs the browser into the GUI proxy origin."""
    if not get_settings().gui_proxy_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="gui proxy disabled")
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )
    await gui_tunnels.ensure(instance_id)  # start this instance's forwarder on demand
    # Ensure this instance's vhost exists in the proxy *now* — robust against a
    # startup push that raced gui-proxy's boot, or a gui-proxy restart (no-op when
    # the proxy is off or already in sync).
    await gui_caddy.reconcile(session)
    token = sign_gui_token(instance_id, ttl_seconds=60)  # short-lived handoff
    # Opt-in: replay the firewall's WebUI login through the agent and stash the
    # resulting session cookie so handoff can set it — the browser then lands
    # already authenticated. Failure degrades gracefully to the login page.
    if inst.gui_login_enabled:
        result = await agent.send_command("gui.login", {}, timeout=20)
        if result.get("success") and result.get("cookies"):
            gui_sessions.put(token, result["cookies"], ttl_seconds=60)
        else:
            log.warning(
                "agent.gui_login_failed",
                instance_id=instance_id,
                output=result.get("output"),
            )
    await write_audit(
        session,
        action="agent.gui_open",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return GuiOpenResponse(url=f"{_gui_base_url(inst)}/__orbit/auth?t={token}")


@router.get("/gui/handoff")
async def gui_handoff(t: str) -> RedirectResponse:
    """Exchange a valid handoff token for an origin-scoped orbit_gui cookie (via Caddy)."""
    instance_id = verify_gui_token(t)
    if instance_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid handoff token")
    resp = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        COOKIE_NAME,
        sign_gui_token(instance_id, ttl_seconds=8 * 3600),  # browsing session
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    # Opt-in auto-login (see §18): replay the firewall's own session cookie onto
    # this origin so the browser is already authenticated when it reaches the GUI.
    for name, value in gui_sessions.pop(t):
        resp.set_cookie(name, value, httponly=True, secure=True, samesite="lax", path="/")
    return resp


def _instance_from_host(host: str) -> int | None:
    """Extract the instance id from a `gui-<id>.…` proxy origin (Traefik wildcard)."""
    m = re.match(r"gui-(\d+)\.", host or "")
    return int(m.group(1)) if m else None


@router.get("/gui/authcheck")
async def gui_authcheck(request: Request, instance: int | None = None) -> dict:
    """forward_auth target: 200 only if the orbit_gui cookie is valid for THIS instance.

    Zero-I/O (HMAC verify only) — runs on every asset. The origin's instance comes
    from the `instance` query (Caddy per-port dev) or the `gui-<id>` Host (Traefik
    wildcard prod). The cookie's instance must equal it — a cookie minted for one
    firewall can't satisfy another's gate (cross-tenant defense).
    """
    if instance is None:
        # Traefik ForwardAuth puts the real origin in X-Forwarded-Host; the auth
        # subrequest's own Host is the auth server. Prefer the forwarded one.
        host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
        instance = _instance_from_host(host)
    if instance is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no instance")
    token = request.cookies.get(COOKIE_NAME, "")
    cookie_instance = verify_gui_token(token) if token else None
    if cookie_instance is None or cookie_instance != instance:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="gui auth required")
    return {"ok": True}


# --- Lifecycle: uninstall + enrollment (§16 chunk C) -------------------------


@router.post("/instances/{instance_id}/agent/uninstall")
async def uninstall_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Tell the connected agent to remove itself, then drop agent mode.

    The agent acks and a detached script tears it down (supervisor first); on a
    successful ack we revoke the token and fall back to direct transport so the
    dashboard stops expecting a push agent.
    """
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )

    result = await agent.send_command("agent.uninstall", {"deprovision": True}, timeout=30)
    if result.get("success"):
        inst.transport = Transport.DIRECT.value
        inst.agent_token = None
        hub.unregister(instance_id)

    await write_audit(
        session,
        action="agent.uninstall",
        result="ok" if result.get("success") else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"result": result},
    )
    await session.commit()
    return {"sent": True, "result": result}


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


class EnrollCodeResponse(BaseModel):
    code: str
    instance_id: int
    expires_at: str


class EnrollRequest(BaseModel):
    code: str


class EnrollResponse(BaseModel):
    agent_token: str
    instance_id: int


@router.post("/instances/{instance_id}/agent/enroll-code", response_model=EnrollCodeResponse)
async def create_enroll_code(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> EnrollCodeResponse:
    """Mint a one-time, 1-hour enrollment code for an instance (admin only).

    The agent trades it at /agent/enroll for this instance's token, so the token
    never has to be pasted by hand. Only the code's SHA-256 is stored.
    """
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    code = secrets.token_urlsafe(24)
    expires_at = datetime.now(UTC) + timedelta(hours=1)
    session.add(
        EnrollmentCode(
            code_hash=_hash_code(code),
            instance_id=instance_id,
            expires_at=expires_at,
        )
    )
    await write_audit(
        session,
        action="agent.enroll_code",
        result="ok",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
    )
    await session.commit()
    return EnrollCodeResponse(code=code, instance_id=instance_id, expires_at=expires_at.isoformat())


@router.post("/agent/enroll", response_model=EnrollResponse)
async def enroll_agent(
    payload: EnrollRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> EnrollResponse:
    """Public: exchange a valid one-time code for an instance's agent token.

    Unauthenticated attack surface → rate-limited per IP with the login limiter.
    The code must be unused and unexpired; it is consumed on success.
    """
    ip = client_ip(request)
    if limiter.is_locked(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many attempts; try again later",
        )

    row = (
        await session.execute(
            select(EnrollmentCode).where(EnrollmentCode.code_hash == _hash_code(payload.code))
        )
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    # MariaDB DATETIME reads back naive (still UTC) — tag it before comparing.
    expired = row is not None and _as_utc(row.expires_at) < now
    if row is None or row.used_at is not None or expired:
        limiter.record_failure(ip)
        await write_audit(
            session,
            action="agent.enroll",
            result="denied",
            source_ip=ip,
            detail={"reason": "invalid_or_expired"},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired code"
        )

    inst = await session.get(Instance, row.instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="instance not found")

    limiter.record_success(ip)
    if not inst.agent_token:
        inst.agent_token = secrets.token_urlsafe(48)
    inst.transport = Transport.PUSH.value
    row.used_at = now

    await write_audit(
        session,
        action="agent.enroll",
        result="ok",
        target_type="instance",
        target_id=str(inst.id),
        source_ip=ip,
    )
    await session.commit()
    return EnrollResponse(agent_token=inst.agent_token, instance_id=inst.id)


@router.get("/instances/{instance_id}/agent/token")
async def get_agent_token(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> dict:
    """Return the stored agent token for an instance (agent mode must be enabled)."""
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if not inst.agent_mode or inst.agent_token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent not enabled")
    return {"agent_token": inst.agent_token}


@router.get("/agent/script", include_in_schema=False)
async def download_agent_script() -> FileResponse:
    """Serve orbit_agent.py for direct download on OPNsense (no auth required)."""
    script = _AGENT_DIR / "orbit_agent.py"
    if not script.exists():
        raise HTTPException(status_code=404, detail="agent script not available")
    return FileResponse(str(script), media_type="text/x-python", filename="orbit_agent.py")


@router.get("/agent/rc", include_in_schema=False)
async def download_agent_rc() -> FileResponse:
    """Serve the rc.d service script for direct download on OPNsense (no auth required)."""
    rc = _AGENT_DIR / "rc.d" / "orbit_agent"
    if not rc.exists():
        raise HTTPException(status_code=404, detail="rc script not available")
    return FileResponse(str(rc), media_type="text/plain", filename="orbit_agent")


@router.get("/agent/run", include_in_schema=False)
async def download_agent_supervisor() -> FileResponse:
    """Serve run-agent.sh (the supervisor) for direct download (no auth required)."""
    sup = _AGENT_DIR / "run-agent.sh"
    if not sup.exists():
        raise HTTPException(status_code=404, detail="supervisor script not available")
    return FileResponse(str(sup), media_type="text/plain", filename="run-agent.sh")
