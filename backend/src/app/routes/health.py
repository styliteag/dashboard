"""Liveness/readiness endpoint — see US-7.1."""
from __future__ import annotations

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.db.base import get_engine

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(response: Response) -> dict[str, str]:
    """Returns 200 if DB is reachable, 503 otherwise."""
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return {"status": "ok", "db": "ok"}
    except Exception as exc:  # noqa: BLE001 — health endpoint should report any failure
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "degraded", "db": "error", "detail": str(exc)}
