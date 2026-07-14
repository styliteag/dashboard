"""Pure-ASGI GeoIP enforcement (DR-G2). BaseHTTPMiddleware is banned in this
repo (breaks streaming/WS) — this class speaks raw ASGI for both http and
websocket scopes.

Exemption order is part of the security contract, mirror of the ADR:
kill switch → non-/api paths (static bundle stays servable, everything that
matters lives under /api) → agent/enroll endpoints (firewalls connect from
customer sites worldwide) → orbit_ API keys (machine reads) → whitelist →
country allowlist.
"""

from __future__ import annotations

import json
import time

import structlog

from app.config import get_settings
from app.geoip import crowdsec, denials, dyndns, lookup
from app.geoip.rules import decide
from app.geoip.store import current_rules
from app.net import pick_client_ip

log = structlog.get_logger("app.geoip")

# Agent-facing endpoints: authenticated by agent token / enroll code, reachable
# from any customer site. /api/health serves uptime probes.
# The two /api/gui/ paths are the GUI-proxy's forward_auth/handoff subrequests:
# they arrive container-to-container (Caddy/Traefik → app:80), so the "client
# IP" here is always the proxy container's Docker address — a private IP with
# no GeoIP country. Geo-checking them only misfires (prod incident 2026-07-14:
# every GUI open logged a no_country denial for the docker-network IP and the
# proxy gate failed). The real protection sits elsewhere: gui/open runs on the
# geo-checked dashboard session, handoff burns a one-time token, authcheck
# verifies the per-instance HMAC cookie. Do not exempt all of /api/gui/.
_EXEMPT_PREFIXES = (
    "/api/ws/agent",
    "/api/ws/tunnel",
    "/api/agent/enroll",
    "/api/health",
    "/api/gui/authcheck",
    "/api/gui/handoff",
)

_DENY_BODY = json.dumps({"detail": "access restricted from your location"}).encode()

# Denial-log throttle: one line per IP per window, so a scripted scanner can't
# flood the log. Process-local, bounded.
_LOG_WINDOW = 10.0
_last_logged: dict[str, float] = {}


def _should_log(ip: str) -> bool:
    now = time.monotonic()
    if len(_last_logged) > 1000:
        _last_logged.clear()
    if now - _last_logged.get(ip, 0.0) >= _LOG_WINDOW:
        _last_logged[ip] = now
        return True
    return False


def _header(scope: dict, name: bytes) -> str | None:
    for key, value in scope.get("headers") or ():
        if key == name:
            return value.decode("latin-1")
    return None


def evaluate_scope(scope: dict) -> tuple[bool, str, str | None, str | None]:
    """(allowed, reason, ip, country) for an http/websocket ASGI scope.

    Pure apart from reads of process-local caches — unit tests drive this
    directly with synthetic scopes.
    """
    path = scope.get("path", "")
    if not path.startswith("/api/") or path.startswith(_EXEMPT_PREFIXES):
        return True, "exempt_path", None, None
    if get_settings().geoip_disable:
        return True, "kill_switch", None, None
    rules = current_rules()
    # CrowdSec (DR-G8) has its own switch and applies even when the country
    # restriction is off — only both-off short-circuits here.
    blocklist_on = crowdsec.active()
    if not rules.restricting and not blocklist_on:
        return True, "not_restricting", None, None
    auth = _header(scope, b"authorization") or ""
    if auth.lower().startswith("bearer orbit_"):
        return True, "api_key", None, None
    peer = scope.get("client")
    ip = pick_client_ip(_header(scope, b"x-forwarded-for"), peer[0] if peer else None)
    db_ok = lookup.db_available()
    country = lookup.country_for(ip) if db_ok else None
    decision = decide(
        ip,
        rules,
        country,
        dyndns.resolved_ips(),
        db_ok,
        banned=crowdsec.is_banned if blocklist_on else None,
    )
    return decision.allowed, decision.reason, ip, country


class GeoipMiddleware:
    def __init__(self, app):  # noqa: ANN001 — ASGI app callable
        self.app = app

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        allowed, reason, ip, country = evaluate_scope(scope)
        if allowed:
            if reason == "db_unavailable":
                denials.record_fail_open()
                if _should_log(ip or "-"):
                    log.error("geoip.db_unavailable_fail_open", ip=ip)
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        # Mark the scope so the (outer) access-log middleware doesn't double-count
        # this request as an anonymous dashboard access — it's already a denial.
        scope["orbit.geoip_denied"] = True
        # Counters/ring buffer record EVERY denial (bounded structures); only
        # the log line is throttled.
        denials.record(ip, country, path, reason)
        if _should_log(ip or "-"):
            log.warning("geoip.denied", ip=ip, country=country, path=path, reason=reason)
        if path == "/api/auth/login":
            await self._audit_login_denial(ip, country, reason)
        if scope["type"] == "websocket":
            # Rejecting before accept fails the handshake with 403.
            await send({"type": "websocket.close", "code": 4403})
            return
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": _DENY_BODY})

    @staticmethod
    async def _audit_login_denial(ip: str | None, country: str | None, reason: str) -> None:
        """Login attempts are the one denial worth an audit row (rare + high
        signal); auditing every blocked request would let a scanner write-flood
        the audit table."""
        from app.audit.log import write_audit  # local imports: avoid cycles
        from app.db.base import get_sessionmaker

        try:
            async with get_sessionmaker()() as session:
                await write_audit(
                    session,
                    action="auth.login",
                    result="denied",
                    detail={"reason": "geo_blocked", "country": country or "", "why": reason},
                    source_ip=ip,
                )
                await session.commit()
        except Exception as exc:  # noqa: BLE001 — an audit hiccup must not 500 the deny
            log.warning("geoip.audit_failed", error=str(exc))
