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

from app.net import client_ip

log = structlog.get_logger("app.http")

_QUIET_PATHS = frozenset({"/api/health"})

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
            duration_ms = round((time.perf_counter() - start) * 1000, 1)
            getattr(log, _level(status, path, duration_ms))(
                "http",
                ip=client_ip(HTTPConnection(scope)),
                method=scope["method"],
                path=path,
                status=status,
                duration_ms=duration_ms,
                user_id=(scope.get("session") or {}).get("user_id"),
            )

    async def _websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        # The only place the external IP of an agent/tunnel connection surfaces:
        # the hub's agent.connected/disconnected events carry no address.
        start = time.perf_counter()
        ip = client_ip(HTTPConnection(scope))
        path = scope["path"]

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "websocket.accept":
                log.info("ws.open", ip=ip, path=path)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            log.info("ws.close", ip=ip, path=path, duration_s=round(time.perf_counter() - start, 1))
