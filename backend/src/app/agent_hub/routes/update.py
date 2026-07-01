"""Agent code delivery: self-update push endpoints + script downloads."""

from __future__ import annotations

import base64
import hashlib
import os
import re
from pathlib import Path

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import ConnectedAgent, hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.db.base import get_session
from app.db.models import Instance, User
from app.net import client_ip

log = structlog.get_logger("app.agent_hub.routes")

router = APIRouter(tags=["agent"])

# Agent files are baked into /app/agent/ in the production container.
# Override via AGENT_DIR env var for local dev.
_AGENT_DIR = Path(os.environ.get("AGENT_DIR", "/app/agent"))


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


async def _push_update(agent: ConnectedAgent, params: dict) -> dict:
    """Send agent.update to one connection and persist the outcome on it.

    A rejection is pinned as ``last_update_error`` so the reason stays visible in
    the GUI (the agent stays connected when it refuses an update). A success
    restarts the agent → fresh connection, which clears it.
    """
    result = await agent.send_command("agent.update", params, timeout=30)
    if result.get("success"):
        agent.last_update_error = None
        agent.last_update_version = None
    else:
        agent.last_update_error = result.get("output") or "update failed"
        agent.last_update_version = params["version"]
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

    result = await _push_update(agent, params)

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
        result = await _push_update(agent, params)
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
