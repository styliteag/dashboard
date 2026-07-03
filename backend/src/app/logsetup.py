"""Unified logging: structlog and stdlib (uvicorn, libraries) through one pipeline.

Root level = ``DASH_LOG_LEVEL``; the ``app.audit`` event stream is pinned to INFO
so security/operational events (logins, lockouts, device up/down) stay visible in
docker logs even at level=warning. Rendering — human-readable key-value vs JSON
lines — is chosen by ``DASH_LOG_FORMAT``.

uvicorn's access log is replaced by ``app.http_log.AccessLogMiddleware`` (which
logs the trusted-proxy-aware external client IP); ``uvicorn.access`` is silenced
here as well so ad-hoc invocations without ``--no-access-log`` stay clean.
"""

from __future__ import annotations

import logging
import sys

import structlog

AUDIT_LOGGER = "app.audit"

_SHARED_PROCESSORS = [
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso"),
]

# Our handler on the root logger. Tracked so a re-configure (create_app + lifespan
# re-apply after DB overrides load) replaces it instead of stacking duplicates.
# Never clear all root handlers — that would strip pytest's caplog handler.
_handler: logging.Handler | None = None


def _renderers(fmt: str) -> list:
    if fmt == "json":
        return [structlog.processors.format_exc_info, structlog.processors.JSONRenderer()]
    return [structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())]


def configure_logging(level: str, fmt: str = "console") -> None:
    """Idempotent: safe to call at import time and again from lifespan."""
    global _handler

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            *_renderers(fmt),
        ],
        foreign_pre_chain=_SHARED_PROCESSORS,
    )
    root = logging.getLogger()
    if _handler is not None:
        root.removeHandler(_handler)
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(formatter)
    root.addHandler(_handler)
    root_level = getattr(logging, level.upper(), logging.INFO)
    root.setLevel(root_level)

    # uvicorn lifecycle/error logs join the unified pipeline; its access log is
    # replaced by AccessLogMiddleware. Level = max(root, INFO): uvicorn pins INFO
    # at process start, which would leak "connection open" at level=warning — but
    # plain root inheritance would surface the websockets library's per-frame
    # DEBUG traces (< TEXT, > PING keepalives) at level=debug.
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(max(root_level, logging.INFO))
    access = logging.getLogger("uvicorn.access")
    access.handlers.clear()
    access.propagate = False

    logging.getLogger(AUDIT_LOGGER).setLevel(logging.INFO)

    # Library plumbing that floods INFO/DEBUG (poll cycles emit dozens of
    # httpcore/apscheduler/asyncssh lines each). The app has its own events for
    # those paths (poll.ok/poll.error, notify.*); real library problems still warn.
    for name in ("apscheduler", "httpx", "httpcore", "asyncssh"):
        logging.getLogger(name).setLevel(logging.WARNING)

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *_SHARED_PROCESSORS,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        # The lifespan re-configure must take effect on already-created module-level
        # loggers, so never freeze the config into them.
        cache_logger_on_first_use=False,
    )
