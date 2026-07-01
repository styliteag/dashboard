"""Local API relay: proxy dashboard HTTP requests to the firewall via the agent."""

from __future__ import annotations

import base64
import time

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import require_write
from app.db.base import get_session
from app.db.models import Instance, User
from app.net import client_ip

log = structlog.get_logger("app.agent_hub.routes")

router = APIRouter(tags=["agent"])

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
