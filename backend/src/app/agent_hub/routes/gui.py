"""GUI proxy auth gate: handoff token mint/exchange + forward_auth check (§18)."""

from __future__ import annotations

import re
from urllib.parse import quote

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_hub import gui_caddy
from app.agent_hub.gui_auth import COOKIE_NAME, sign_gui_token, verify_gui_token
from app.agent_hub.gui_session import gui_sessions
from app.agent_hub.gui_tunnel import gui_tunnels
from app.agent_hub.hub import hub
from app.audit.log import write_audit
from app.auth.deps import require_write
from app.config import get_settings
from app.db.base import get_session
from app.db.models import Instance, User
from app.instances.service import get_instance
from app.net import client_ip

log = structlog.get_logger("app.agent_hub.routes")

router = APIRouter(tags=["agent"])

# --- GUI proxy auth gate (token handoff + forward_auth, see §18) -------------


def _safe_next(path: str | None) -> str:
    """Clamp a handoff deep-link to a same-origin absolute path (open-redirect defense).

    Accepts only "/..." — rejects absolute URLs, protocol-relative "//host", and
    backslash variants some browsers normalize to "//". Anything else → "/".
    """
    if path and path.startswith("/") and not path.startswith("//") and "\\" not in path:
        return path
    return "/"


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
    path: str | None = Query(
        None, description="Deep-link path inside the GUI, e.g. /ui/ipsec/sessions"
    ),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(require_write),
) -> GuiOpenResponse:
    """Mint a short-lived handoff URL that logs the browser into the GUI proxy origin."""
    if not get_settings().gui_proxy_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="gui proxy disabled")
    inst = await get_instance(session, instance_id, user)
    if inst is None:
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
    url = f"{_gui_base_url(inst)}/__orbit/auth?t={token}"
    nxt = _safe_next(path)
    if nxt != "/":
        url += f"&next={quote(nxt, safe='/')}"
    return GuiOpenResponse(url=url)


@router.get("/gui/handoff")
async def gui_handoff(
    t: str, next_path: str | None = Query(None, alias="next")
) -> RedirectResponse:
    """Exchange a valid handoff token for an origin-scoped orbit_gui cookie (via Caddy)."""
    instance_id = verify_gui_token(t)
    if instance_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid handoff token")
    resp = RedirectResponse(url=_safe_next(next_path), status_code=status.HTTP_302_FOUND)
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
