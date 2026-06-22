"""Agent WebSocket endpoint + REST routes for agent management."""

from __future__ import annotations

import json
import os
import secrets
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


@router.get("/instances/{instance_id}/agent/status", response_model=AgentStatusResponse)
async def agent_status(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(current_user),
) -> AgentStatusResponse:
    inst = await session.get(Instance, instance_id)
    if inst is None or inst.deleted_at is not None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    return AgentStatusResponse(
        instance_id=instance_id,
        instance_name=inst.name,
        agent_mode=inst.agent_mode,
        agent_connected=hub.is_connected(instance_id),
        agent_last_seen=inst.agent_last_seen.isoformat() if inst.agent_last_seen else None,
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


@router.get("/agents/connected")
async def list_connected_agents(
    _user: User = Depends(current_user),
) -> list[dict]:
    """List all currently connected agents."""
    return hub.list_connected()


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
