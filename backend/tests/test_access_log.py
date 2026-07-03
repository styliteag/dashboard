"""Tests for the access-log middleware (external client IP, level mapping, WS)."""

from __future__ import annotations

import types

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from structlog.testing import capture_logs

from app import net
from app.http_log import AccessLogMiddleware


def _app() -> FastAPI:
    app = FastAPI()

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    @app.get("/api/ok")
    async def ok():
        return {"ok": True}

    @app.get("/api/limited")
    async def limited():
        raise HTTPException(status_code=429, detail="slow down")

    @app.get("/api/boom")
    async def boom():
        raise RuntimeError("kaputt")

    app.add_middleware(AccessLogMiddleware)
    return app


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test"
    )


def _http_events(cap) -> list[dict]:
    return [e for e in cap if e["event"] == "http"]


@pytest.mark.asyncio
async def test_logs_external_ip_from_xff(monkeypatch) -> None:
    monkeypatch.setattr(net, "get_settings", lambda: types.SimpleNamespace(trusted_proxy_hops=1))
    with capture_logs() as cap:
        async with _client(_app()) as client:
            resp = await client.get("/api/ok", headers={"x-forwarded-for": "spoofed, 1.2.3.4"})
    assert resp.status_code == 200
    (event,) = _http_events(cap)
    assert event["ip"] == "1.2.3.4"
    assert event["method"] == "GET"
    assert event["path"] == "/api/ok"
    assert event["status"] == 200
    assert "duration_ms" in event
    assert event["log_level"] == "info"


@pytest.mark.asyncio
async def test_health_is_debug() -> None:
    with capture_logs() as cap:
        async with _client(_app()) as client:
            await client.get("/api/health")
    (event,) = _http_events(cap)
    assert event["log_level"] == "debug"


@pytest.mark.asyncio
async def test_status_level_mapping() -> None:
    with capture_logs() as cap:
        async with _client(_app()) as client:
            assert (await client.get("/api/limited")).status_code == 429
            assert (await client.get("/api/boom")).status_code == 500
            assert (await client.get("/api/missing")).status_code == 404
    events = _http_events(cap)
    levels = {e["path"]: e["log_level"] for e in events}
    assert levels["/api/limited"] == "warning"
    assert levels["/api/boom"] == "error"
    assert levels["/api/missing"] == "info"


@pytest.mark.asyncio
async def test_websocket_open_close_logged() -> None:
    inner_messages = []

    async def ws_app(scope, receive, send):
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.close", "code": 1000})

    mw = AccessLogMiddleware(ws_app)
    scope = {
        "type": "websocket",
        "path": "/api/ws/agent",
        "headers": [(b"x-forwarded-for", b"5.6.7.8")],
        "client": ("10.0.0.1", 1234),
    }

    async def receive():
        return {"type": "websocket.connect"}

    async def send(message):
        inner_messages.append(message)

    with capture_logs() as cap:
        await mw(scope, receive, send)

    events = {e["event"]: e for e in cap}
    assert "ws.open" in events
    assert "ws.close" in events
    assert events["ws.open"]["path"] == "/api/ws/agent"
    assert events["ws.open"]["ip"]
    assert inner_messages[0]["type"] == "websocket.accept"
