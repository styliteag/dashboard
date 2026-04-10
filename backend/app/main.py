"""FastAPI application factory."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.auth.bootstrap import ensure_admin
from app.auth.routes import router as auth_router
from app.config import get_settings
from app.db.base import dispose_engine
from app.instances.routes import router as instances_router
from app.opnsense.registry import registry
from app.routes import health


def _configure_logging(level: str) -> None:
    logging.basicConfig(level=level.upper(), format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    log = structlog.get_logger("app.lifespan")
    log.info("startup")
    try:
        await ensure_admin()
    except Exception as exc:  # noqa: BLE001 — log and continue; health endpoint will report DB issues
        log.error("admin_bootstrap.failed", error=str(exc))
    try:
        yield
    finally:
        log.info("shutdown")
        await registry.close_all()
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    _configure_logging(settings.log_level)

    app = FastAPI(
        title="opnsense-dash",
        version="0.0.1",
        lifespan=lifespan,
    )

    # Signed session cookies. Master key doubles as the session secret —
    # rotating it logs everyone out, which is intentional.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.master_key or "dev-only-not-secret",
        session_cookie="dash_session",
        https_only=settings.env != "dev",
        same_site="strict",
        max_age=12 * 60 * 60,  # 12h sliding window
    )

    app.include_router(health.router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(instances_router, prefix="/api")
    return app


app = create_app()
