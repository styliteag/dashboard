"""Access-log ASGI middleware — replaces uvicorn's access log.

Logs the EXTERNAL client IP via ``client_ip()`` (trusted-proxy-hops aware,
``DASH_TRUSTED_PROXY_HOPS``) instead of the reverse proxy's internal address.
Pure ASGI on purpose: ``BaseHTTPMiddleware`` buffers responses and breaks
streaming/background tasks.
"""

from __future__ import annotations

import time

import structlog
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.access import store as access_store
from app.net import client_ip

log = structlog.get_logger("app.http")

_QUIET_PATHS = frozenset({"/api/health"})

# Machine/agent traffic that is not "somebody using the dashboard" — kept out
# of the access accounting (mirrors the GeoIP exempt list + health probes).
_ACCESS_SKIP_PREFIXES = (
    "/api/ws/agent",
    "/api/ws/tunnel",
    "/api/agent/enroll",
    "/api/health",
)


def _count_access(scope: Scope, ip: str, method: str, path: str, status: int) -> None:
    """Feed the access accounting (ADR docs/access-log.md, DR-AL2/AL8).

    user session → counted + sampled (+ last_seen stamp); anonymous → counted
    without an IP (data minimisation); orbit_ API keys are counted in
    ``read_principal`` where the key identity is known — skipped here so a
    scrape is never double-counted; GeoIP/CrowdSec denials are already counted
    by the denial store — the gate marks the scope.
    """
    if not path.startswith("/api/") or path.startswith(_ACCESS_SKIP_PREFIXES):
        return
    if scope.get("orbit.geoip_denied"):
        return
    for name, value in scope.get("headers") or ():
        if name == b"authorization" and value.lower().startswith(b"bearer orbit_"):
            return
    sess = scope.get("session") or {}
    user_id = sess.get("user_id")
    if user_id:
        access_store.record_request(
            "user", str(user_id), ip, method, path, status, user_id=user_id, sid=sess.get("sid")
        )
    else:
        access_store.record_request("anon", "anon", None, method, path, status)


# A request slower than this logs at warning — on the single-worker loop a
# slow request is a capacity signal, not noise (scaling observability).
SLOW_REQUEST_MS = 1000.0


def _level(status: int, path: str, duration_ms: float = 0.0) -> str:
    # Raw 4xx stay at info: real security denials (bad password, IP lock, enroll
    # denied) already reach the always-visible app.audit stream with usernames.
    if status >= 500:
        return "error"
    if status == 429 or duration_ms > SLOW_REQUEST_MS:
        return "warning"
    if path in _QUIET_PATHS and status < 400:
        return "debug"
    return "info"


class AccessLogMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await self._websocket(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.perf_counter()
        # An exception before response.start becomes a 500 (ServerErrorMiddleware
        # sits above us).
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            path = scope["path"]
            ip = client_ip(HTTPConnection(scope))
            duration_ms = round((time.perf_counter() - start) * 1000, 1)
            getattr(log, _level(status, path, duration_ms))(
                "http",
                ip=ip,
                method=scope["method"],
                path=path,
                status=status,
                duration_ms=duration_ms,
                user_id=(scope.get("session") or {}).get("user_id"),
            )
            _count_access(scope, ip, scope["method"], path, status)

    async def _websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        # The only place the external IP of an agent/tunnel connection surfaces:
        # the hub's agent.connected/disconnected events carry no address.
        start = time.perf_counter()
        ip = client_ip(HTTPConnection(scope))
        path = scope["path"]

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "websocket.accept":
                log.info("ws.open", ip=ip, path=path)
                # One accepted WS = one access (DR-AL2); the session scope is
                # populated by the time the app accepts.
                _count_access(scope, ip, "WS", path, 101)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log.info("ws.close", ip=ip, path=path, duration_s=round(time.perf_counter() - start, 1))
