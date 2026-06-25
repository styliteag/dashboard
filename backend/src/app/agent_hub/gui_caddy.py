"""Build the prod GUI-proxy Caddyfile from the DB and push it via the admin API.

The public host is now a per-instance ``slug`` (``gui-<slug>.<domain>``), so Caddy
can no longer *compute* host→port — the binding lives in the DB. On every instance
create / slug-change / delete (and at startup) the backend rebuilds the Caddyfile
and POSTs it to Caddy's admin ``/load`` endpoint (no container restart).

The forwarder port stays ``14400 + id`` (stable across renames). The instance id is
baked into each vhost's ``forward_auth ?instance=<id>`` — so authcheck needs no
host parsing and the id is server-side (not client-spoofable). The TLS upstream
port must be a literal (Caddy forbids a runtime placeholder there), which is exactly
why the file is regenerated rather than parameterised at request time.

See docs/agent-architecture.md §18 and README "Firewall GUI proxy".
"""

from __future__ import annotations

from collections.abc import Iterable

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Instance

log = structlog.get_logger("app.gui_caddy")

FORWARDER_BASE = 14400  # instance forwarder port = FORWARDER_BASE + id (see gui_tunnel)

# Global options: admin API on :2019 so the backend can hot-load config; no
# auto-HTTPS (external Traefik terminates TLS). Bind admin to all interfaces so a
# sibling container can reach it — keep :2019 OFF the host (internal network only).
_GLOBAL = """\
# GENERATED — pushed by the backend via Caddy's admin API (app/agent_hub/gui_caddy.py).
{
\tadmin 0.0.0.0:2019
\tauto_https off
}

# One vhost body, parameterised by (forwarder-port, instance-id) at adapt time.
(gui_vhost) {
\t@orbit path /__orbit/*
\thandle @orbit {
\t\trewrite * /api/gui/handoff?{query}
\t\treverse_proxy {$ORBIT_GUI_APP:app:80}
\t}
\thandle {
\t\tforward_auth {$ORBIT_GUI_APP:app:80} {
\t\t\turi /api/gui/authcheck?instance={args[1]}
\t\t}
\t\treverse_proxy {$ORBIT_GUI_FWD_HOST:app}:{args[0]} {
\t\t\ttransport http {
\t\t\t\ttls
\t\t\t\ttls_insecure_skip_verify
\t\t\t}
\t\t}
\t}
}
"""


def build_caddyfile(instances: Iterable[tuple[str, int]]) -> str:
    """Render the GUI-proxy Caddyfile for ``(slug, id)`` pairs (empty = bootstrap)."""
    lines = [_GLOBAL, "\nhttp://*.{$ORBIT_GUI_DOMAIN} {\n"]
    for slug, instance_id in instances:
        lines.append(f"\t@gui-{slug} host gui-{slug}.{{$ORBIT_GUI_DOMAIN}}\n")
        lines.append(
            f"\thandle @gui-{slug} {{\n"
            f"\t\timport gui_vhost {FORWARDER_BASE + instance_id} {instance_id}\n"
            f"\t}}\n"
        )
    lines.append("}\n")
    return "".join(lines)


def bootstrap_caddyfile() -> str:
    """The startup config Caddy mounts before the backend pushes the live one."""
    return build_caddyfile([])


async def _live_instances(session: AsyncSession) -> list[tuple[str, int]]:
    rows = (
        await session.execute(
            select(Instance.slug, Instance.id)
            .where(Instance.deleted_at.is_(None))
            .order_by(Instance.id)
        )
    ).all()
    return [(slug, instance_id) for slug, instance_id in rows]


async def reconcile(session: AsyncSession) -> bool:
    """Rebuild the Caddyfile from live instances and hot-load it. Best-effort.

    No-op (returns False) when the GUI proxy is off or no admin URL is configured.
    A push failure is logged, never raised — a transient Caddy outage must not break
    instance CRUD; the next change (or a restart) re-pushes.
    """
    settings = get_settings()
    if not settings.gui_proxy_enabled or not settings.gui_caddy_admin_url:
        return False
    config = build_caddyfile(await _live_instances(session))
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                settings.gui_caddy_admin_url,
                content=config.encode(),
                headers={"Content-Type": "text/caddyfile"},
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("gui_caddy.push_failed", error=str(exc), url=settings.gui_caddy_admin_url)
        return False
    log.info("gui_caddy.pushed", vhosts=config.count("@gui-"))
    return True
