"""FastAPI application factory."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from app.config import get_settings
from app.db.base import dispose_engine
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
        yield
    finally:
        log.info("shutdown")
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    _configure_logging(settings.log_level)

    app = FastAPI(
        title="opnsense-dash",
        version="0.0.1",
        lifespan=lifespan,
    )
    app.include_router(health.router, prefix="/api")
    return app


app = create_app()
