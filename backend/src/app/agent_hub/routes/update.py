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
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import ConnectedAgent, hub
from app.audit.log import write_audit
from app.auth.deps import current_user, require_write
from app.auth.scope import scope_clause
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances.service import get_instance
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


_CHECKMK_VENDOR = "vendor/check_mk_agent.linux"


def _checkmk_update_params() -> dict | None:
    """checkmk.update params: the vendored script + its offline Ed25519 .sig.

    Same relay-only model as the agent self-update — the dashboard never holds
    the signing key, the agent verifies against its baked _UPDATE_PUBKEY.
    """
    try:
        code = (_AGENT_DIR / _CHECKMK_VENDOR).read_bytes()
    except OSError:
        return None
    try:
        signature = (_AGENT_DIR / (_CHECKMK_VENDOR + ".sig")).read_text().strip()
    except OSError:
        signature = ""
    return {
        "sha256": hashlib.sha256(code).hexdigest(),
        "code": base64.b64encode(code).decode(),
        "signature": signature,
    }


async def maybe_deploy_checkmk(agent: ConnectedAgent) -> None:
    """Keep a linux node's Checkmk script at the vendored pin (§25/DR-10).

    Fired after hello: when the agent reports a different script sha256 than
    the vendored copy this container serves, push the signed script via
    checkmk.update. Best-effort — a failure logs and never touches the
    connection; the agent refuses anything unsigned, so a compromised
    backend cannot ship arbitrary root code.
    """
    if agent.platform != "linux":
        return
    params = _checkmk_update_params()
    if params is None or agent.checkmk_sha256 == params["sha256"]:
        return
    try:
        result = await agent.send_command("checkmk.update", params, timeout=60)
    except Exception:
        log.warning("agent.checkmk_deploy_failed", instance_id=agent.instance_id)
        return
    if result.get("success"):
        agent.checkmk_sha256 = params["sha256"]
        log.info(
            "agent.checkmk_deployed",
            instance_id=agent.instance_id,
            sha=params["sha256"][:12],
        )
    else:
        log.warning(
            "agent.checkmk_deploy_rejected",
            instance_id=agent.instance_id,
            output=str(result.get("output", ""))[:200],
        )


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
    inst = await get_instance(session, instance_id, user)
    if inst is None:
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


async def _visible_instance_ids(session: AsyncSession, user: User) -> set[int] | None:
    """Ids of active instances the user may see; None = unscoped (machine).

    The hub's connected-agents list is in-memory and bypasses every DB WHERE
    clause, so it must be filtered against this set explicitly.
    """
    clause = scope_clause(user)
    if clause is None:
        return None
    rows = (
        await session.execute(select(Instance.id).where(Instance.deleted_at.is_(None), clause))
    ).scalars()
    return set(rows)


@router.get("/agents/connected")
async def list_connected_agents(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
) -> list[dict]:
    """The caller's visible connected agents, annotated with update availability."""
    served = _served_agent_version()
    visible = await _visible_instance_ids(session, user)
    return [
        {
            **a,
            "served_version": served,
            "update_available": bool(
                a["agent_version"] and served and a["agent_version"] != served
            ),
        }
        for a in hub.list_connected()
        if visible is None or a["instance_id"] in visible
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

    visible = await _visible_instance_ids(session, user)
    targets = [
        a
        for a in hub.list_connected()
        if a["agent_version"] != served and (visible is None or a["instance_id"] in visible)
    ]
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


@router.get("/agent/systemd", include_in_schema=False)
async def download_agent_systemd_unit() -> FileResponse:
    """Serve the systemd unit for linux nodes (§25; no auth required)."""
    unit = _AGENT_DIR / "systemd" / "orbit-agent.service"
    if not unit.exists():
        raise HTTPException(status_code=404, detail="systemd unit not available")
    return FileResponse(str(unit), media_type="text/plain", filename="orbit-agent.service")


@router.get("/agent/checkmk", include_in_schema=False)
async def download_checkmk_agent() -> FileResponse:
    """Serve the vendored Checkmk agent for linux nodes (§25; no auth required).

    GPLv2 — vendored unmodified, attributed in THIRD-PARTY-NOTICES.md; the
    shell script is its own complete corresponding source.
    """
    script = _AGENT_DIR / _CHECKMK_VENDOR
    if not script.exists():
        raise HTTPException(status_code=404, detail="checkmk agent not available")
    return FileResponse(str(script), media_type="text/plain", filename="check_mk_agent.linux")
