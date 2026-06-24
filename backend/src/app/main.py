"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.agent_hub.hub import hub
from app.agent_hub.routes import router as agent_router
from app.apikeys.routes import router as apikeys_router
from app.audit.routes import router as audit_router
from app.auth.bootstrap import ensure_admin
from app.auth.routes import router as auth_router
from app.bulk.routes import router as bulk_router
from app.checks.routes import router as checks_router
from app.config import get_settings
from app.db.base import dispose_engine
from app.firmware.routes import router as firmware_router
from app.instances.routes import router as instances_router
from app.ipsec.routes import router as ipsec_router
from app.metrics.routes import router as metrics_router
from app.poller.scheduler import start_scheduler, stop_scheduler
from app.routes import health
from app.system.routes import router as system_router
from app.views.routes import router as views_router
from app.xsense.registry import registry


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
    except Exception as exc:  # noqa: BLE001
        log.error("admin_bootstrap.failed", error=str(exc))

    # Re-hydrate the agent hub's live-status caches from the last persisted
    # snapshots so a backend restart doesn't blank the dashboard until the next push.
    try:
        restored = await hub.hydrate_from_db()
        log.info("hub.hydrated", instances=restored)
    except Exception as exc:  # noqa: BLE001 — never block startup on hydration
        log.error("hub.hydrate_failed", error=str(exc))

    # Start the background poller
    start_scheduler()

    try:
        yield
    finally:
        log.info("shutdown")
        await stop_scheduler()
        await registry.close_all()
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    _configure_logging(settings.log_level)

    app = FastAPI(
        title="Orbit Dashboard",
        version="0.0.1",
        lifespan=lifespan,
    )

    # Same-site Strict trips up some embedded browsers (Cursor's preview) and
    # any setup where the SPA is reached on a different host than the cookie
    # was set on. In prod we still get good CSRF protection because the API
    # and the SPA are served from the same origin (nginx in the combined
    # image) — Lax is sufficient and avoids the edge cases.
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.master_key or "dev-only-not-secret",
        session_cookie="dash_session",
        https_only=settings.env != "dev",
        same_site="lax",
        max_age=12 * 60 * 60,
    )

    app.include_router(health.router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(instances_router, prefix="/api")
    app.include_router(metrics_router, prefix="/api")
    app.include_router(ipsec_router, prefix="/api")
    app.include_router(firmware_router, prefix="/api")
    app.include_router(audit_router, prefix="/api")
    app.include_router(views_router, prefix="/api")
    app.include_router(system_router, prefix="/api")
    app.include_router(bulk_router, prefix="/api")
    app.include_router(agent_router, prefix="/api")
    app.include_router(checks_router, prefix="/api")
    app.include_router(apikeys_router, prefix="/api")
    return app


app = create_app()
