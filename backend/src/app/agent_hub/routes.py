"""Agent WebSocket endpoint + REST routes for agent management."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import current_user
from app.db.base import get_session, get_sessionmaker
from app.db.models import Instance, User
from app.devices.types import Transport

# Agent files are baked into /app/agent/ in the production container.
# Override via AGENT_DIR env var for local dev.
_AGENT_DIR = Path(os.environ.get("AGENT_DIR", "/app/agent"))

router = APIRouter(tags=["agent"])


def _served_agent_version() -> str | None:
    """Parse __version__ from the agent script shipped in this container."""
    try:
        text = (_AGENT_DIR / "opnsense_agent.py").read_text()
    except OSError:
        return None
    m = re.search(r"""^__version__\s*=\s*["']([^"']+)["']""", text, re.MULTILINE)
    return m.group(1) if m else None


def _agent_update_params() -> dict | None:
    """Build the agent.update command params (version, sha256, base64 code), or None."""
    try:
        code = (_AGENT_DIR / "opnsense_agent.py").read_bytes()
    except OSError:
        return None
    return {
        "version": _served_agent_version() or "unknown",
        "sha256": hashlib.sha256(code).hexdigest(),
        "code": base64.b64encode(code).decode(),
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
                }
            )

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

                elif msg_type == "pong":
                    pass

            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        hub.unregister(instance_id)


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


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/instances/{instance_id}/agent/enable", response_model=AgentTokenResponse)
async def enable_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
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
        source_ip=_client_ip(request),
    )
    await session.commit()
    return AgentTokenResponse(instance_id=instance_id, agent_token=token, agent_mode=True)


@router.post("/instances/{instance_id}/agent/disable")
async def disable_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
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
        source_ip=_client_ip(request),
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
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


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
    )


@router.post("/instances/{instance_id}/agent/command")
async def send_agent_command(
    instance_id: int,
    body: dict,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> dict:
    """Send a command to a connected agent."""
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )

    action = body.get("action", "")
    params = body.get("params", {})

    result = await agent.send_command(action, params)

    await write_audit(
        session,
        action=f"agent.command.{action}",
        result="ok" if result.get("success") else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=_client_ip(request),
        detail={"action": action, "result": result},
    )
    await session.commit()
    return result


@router.post("/instances/{instance_id}/agent/update")
async def update_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
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

    result = await agent.send_command("agent.update", params, timeout=30)

    await write_audit(
        session,
        action="agent.update",
        result="ok" if result.get("success") else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=_client_ip(request),
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
    user: User = Depends(current_user),
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
        result = await agent.send_command("agent.update", params, timeout=30)
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
        source_ip=_client_ip(request),
        detail={"served_version": served, "count": len(results)},
    )
    await session.commit()
    return {"served_version": served, "updated": results}


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
    """Serve opnsense_agent.py for direct download on OPNsense (no auth required)."""
    script = _AGENT_DIR / "opnsense_agent.py"
    if not script.exists():
        raise HTTPException(status_code=404, detail="agent script not available")
    return FileResponse(str(script), media_type="text/x-python", filename="opnsense_agent.py")


@router.get("/agent/rc", include_in_schema=False)
async def download_agent_rc() -> FileResponse:
    """Serve the rc.d service script for direct download on OPNsense (no auth required)."""
    rc = _AGENT_DIR / "rc.d" / "opnsense_dash_agent"
    if not rc.exists():
        raise HTTPException(status_code=404, detail="rc script not available")
    return FileResponse(str(rc), media_type="text/plain", filename="opnsense_dash_agent")


@router.get("/agent/run", include_in_schema=False)
async def download_agent_supervisor() -> FileResponse:
    """Serve run-agent.sh (the supervisor) for direct download (no auth required)."""
    sup = _AGENT_DIR / "run-agent.sh"
    if not sup.exists():
        raise HTTPException(status_code=404, detail="supervisor script not available")
    return FileResponse(str(sup), media_type="text/plain", filename="run-agent.sh")
