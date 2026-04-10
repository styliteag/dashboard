"""Smoke test for the health endpoint (no DB required when get_engine is patched)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app


@pytest.mark.asyncio
async def test_health_ok_when_db_reachable() -> None:
    app = create_app()

    fake_conn = AsyncMock()
    fake_conn.execute = AsyncMock(return_value=None)
    fake_engine = MagicMock()
    fake_engine.connect.return_value.__aenter__ = AsyncMock(return_value=fake_conn)
    fake_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("app.routes.health.get_engine", return_value=fake_engine):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "db": "ok"}


@pytest.mark.asyncio
async def test_health_degraded_when_db_fails() -> None:
    app = create_app()

    def boom():
        raise RuntimeError("db down")

    with patch("app.routes.health.get_engine", side_effect=boom):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/health")

    assert resp.status_code == 503
    assert resp.json()["db"] == "error"
