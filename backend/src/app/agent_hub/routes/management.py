"""REST: agent management — enable/disable, status, token, generic command."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.agent_hub.routes.update import _served_agent_version
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.config import get_settings
from app.db.base import get_session
from app.db.models import User
from app.devices.types import Transport
from app.instances.service import get_instance
from app.net import client_ip

log = structlog.get_logger("app.agent_hub.routes")

router = APIRouter(tags=["agent"])


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
    shell_enabled: bool = False  # global: browser terminal to a root PTY (SPIKE, §22)
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
    inst = await get_instance(session, instance_id, user)
    if inst is None:
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
    inst = await get_instance(session, instance_id, user)
    if inst is None:
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
    user: User = Depends(current_user),
) -> AgentStatusResponse:
    inst = await get_instance(session, instance_id, user)
    if inst is None:
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
        shell_enabled=get_settings().shell_enabled,
        platform=connected.platform if connected else None,
        last_update_error=connected.last_update_error if connected else None,
        last_update_version=connected.last_update_version if connected else None,
    )


# Privileged actions that must only run via their dedicated, purpose-built routes —
# never through this generic passthrough. Either they return live credentials (echoed
# to the caller and audit log), or they take curated params the passthrough would let
# a caller forge: `agent.update` binds the pushed code to the container's signed `.sig`
# in `_agent_update_params()`, and `relay.enable`/`http.relay`/`agent.uninstall` carry
# firewall-admin authority. Letting them ride the raw passthrough bypasses that curation.
_INTERNAL_AGENT_ACTIONS = frozenset(
    {"gui.login", "agent.update", "relay.enable", "http.relay", "agent.uninstall"}
)

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
    if await get_instance(session, instance_id, user) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
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


async def _dispatch_agent_action(
    instance_id: int,
    action: str,
    audit_action: str,
    timeout: int,
    request: Request,
    session: AsyncSession,
    user: User,
) -> dict:
    """Shared guard + send + audit for the fixed-action agent buttons."""
    if await get_instance(session, instance_id, user) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    agent = hub.get(instance_id)
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="agent not connected"
        )
    result = await agent.send_command(action, {}, timeout=timeout)
    await write_audit(
        session,
        action=audit_action,
        result="ok" if result.get("success") else "error",
        user_id=user.id,
        target_type="instance",
        target_id=str(instance_id),
        source_ip=client_ip(request),
        detail={"result": _redact_audit(result)},
    )
    await session.commit()
    return {"sent": True, "result": result}


@router.post("/instances/{instance_id}/agent/refresh")
async def refresh_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Force the agent to re-collect its interval-gated metrics now.

    logfiles (hourly), firmware (~12h) and the config backup are normally
    throttled; this pushes a fresh full snapshot on demand (e.g. to heal a
    Log-Events view after a fix, instead of waiting for the next hourly tick).
    """
    return await _dispatch_agent_action(
        instance_id, "refresh.full", "agent.refresh", 60, request, session, user
    )


@router.post("/instances/{instance_id}/agent/reconnect")
async def reconnect_agent(
    instance_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Ask the agent to drop and re-establish its dashboard WebSocket."""
    return await _dispatch_agent_action(
        instance_id, "reconnect", "agent.reconnect", 15, request, session, user
    )


@router.get("/instances/{instance_id}/agent/token")
async def get_agent_token(
    instance_id: int,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> dict:
    """Return the stored agent token for an instance (agent mode must be enabled).

    Write-gated (not just authenticated): the token is a bearer credential to the
    agent WebSocket — anyone holding it can evict the real agent and push forged
    metrics — so a read-only session must not be able to read it.
    """
    inst = await get_instance(session, instance_id, user)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if not inst.agent_mode or inst.agent_token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="agent not enabled")
    return {"agent_token": inst.agent_token}
