"""Liveness/readiness endpoint — see US-7.1."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.db.base import get_engine

router = APIRouter(tags=["health"])

VERSION_FILE = Path("/app/VERSION")


@lru_cache(maxsize=1)
def _read_version() -> str:
    """Read VERSION baked into the image; fall back to APP_VERSION env or 'unknown'."""
    try:
        return VERSION_FILE.read_text().strip() or "unknown"
    except OSError:
        return os.environ.get("APP_VERSION", "unknown")


@router.get("/health")
async def health(response: Response) -> dict[str, str | None]:
    """Returns 200 if DB is reachable, 503 otherwise. Includes app + DB schema versions."""
    version = _read_version()
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            rev_result = await conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
            row = rev_result.first()
            db_revision = row[0] if row else None
        return {"status": "ok", "db": "ok", "version": version, "db_revision": db_revision}
    except Exception as exc:  # noqa: BLE001 — health endpoint should report any failure
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "degraded",
            "db": "error",
            "detail": str(exc),
            "version": version,
            "db_revision": None,
        }
