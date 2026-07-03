"""Scheduled metrics maintenance — raw-metrics retention after the move to MariaDB.

- prune_metrics: delete raw ``metrics`` rows older than ``metrics_retention_days``.
- prune_ipsec_events: delete ``ipsec_tunnel_events`` older than
  ``ipsec_event_retention_days``.

Idempotent and runs off the shared AsyncSession factory.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import text

from app.db.base import get_sessionmaker
from app.logs.store import prune_logfiles as _prune_logfiles_store
from app.settings.store import effective_settings

log = structlog.get_logger("app.maintenance")

# One unbounded DELETE on a large ``metrics`` table held row locks long enough to
# block every concurrent agent-push INSERT, exhausting the connection pool and
# 500ing the API for ~80s each hour. Batches with a commit (lock release) and a
# short pause between them keep the prune invisible to writers.
_DELETE_BATCH_SIZE = 10_000
_BATCH_PAUSE_SECONDS = 0.1


async def _prune_before(table: str, cutoff: datetime) -> int:
    """Batched ``DELETE FROM <table> WHERE ts < cutoff``. Returns rows deleted."""
    stmt = text(f"DELETE FROM {table} WHERE ts < :c LIMIT :n")  # table is an internal constant
    deleted = 0
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        while True:
            result = await session.execute(stmt, {"c": cutoff, "n": _DELETE_BATCH_SIZE})
            await session.commit()
            batch = result.rowcount or 0
            deleted += batch
            if batch < _DELETE_BATCH_SIZE:
                return deleted
            await asyncio.sleep(_BATCH_PAUSE_SECONDS)


async def prune_metrics() -> int:
    """Delete raw metrics older than the retention window. Returns rows deleted."""
    settings = effective_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.metrics_retention_days)
    deleted = await _prune_before("metrics", cutoff)
    if deleted:
        log.info("metrics.pruned", raw=deleted)
    return deleted


async def prune_ipsec_events() -> int:
    """Delete IPsec tunnel events older than the retention window. Returns rows deleted."""
    settings = effective_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.ipsec_event_retention_days)
    deleted = await _prune_before("ipsec_tunnel_events", cutoff)
    if deleted:
        log.info("ipsec_events.pruned", rows=deleted)
    return deleted


async def prune_check_events() -> int:
    """Delete service-check events older than the retention window. Returns rows deleted."""
    settings = effective_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.check_event_retention_days)
    deleted = await _prune_before("check_events", cutoff)
    if deleted:
        log.info("check_events.pruned", rows=deleted)
    return deleted


async def prune_logfiles() -> int:
    """Keep only the newest few log snapshots per (instance, name). Safety net —
    ingest already prunes on write. Returns rows deleted."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        deleted = await _prune_logfiles_store(session)
        await session.commit()
    if deleted:
        log.info("logfiles.pruned", rows=deleted)
    return deleted
