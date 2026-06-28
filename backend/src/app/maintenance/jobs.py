"""Scheduled metrics maintenance — raw-metrics retention after the move to MariaDB.

- prune_metrics: delete raw ``metrics`` rows older than ``metrics_retention_days``.
- prune_ipsec_events: delete ``ipsec_tunnel_events`` older than
  ``ipsec_event_retention_days``.

Idempotent and runs off the shared AsyncSession factory.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import text

from app.db.base import get_sessionmaker
from app.settings.store import effective_settings

log = structlog.get_logger("app.maintenance")


async def prune_metrics() -> int:
    """Delete raw metrics older than the retention window. Returns rows deleted."""
    settings = effective_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.metrics_retention_days)

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(text("DELETE FROM metrics WHERE ts < :c"), {"c": cutoff})
        await session.commit()
    deleted = result.rowcount or 0
    if deleted:
        log.info("metrics.pruned", raw=deleted)
    return deleted


async def prune_ipsec_events() -> int:
    """Delete IPsec tunnel events older than the retention window. Returns rows deleted."""
    settings = effective_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.ipsec_event_retention_days)

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(
            text("DELETE FROM ipsec_tunnel_events WHERE ts < :c"), {"c": cutoff}
        )
        await session.commit()
    deleted = result.rowcount or 0
    if deleted:
        log.info("ipsec_events.pruned", rows=deleted)
    return deleted


async def prune_check_events() -> int:
    """Delete service-check events older than the retention window. Returns rows deleted."""
    settings = effective_settings()
    cutoff = datetime.now(UTC) - timedelta(days=settings.check_event_retention_days)

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(
            text("DELETE FROM check_events WHERE ts < :c"), {"c": cutoff}
        )
        await session.commit()
    deleted = result.rowcount or 0
    if deleted:
        log.info("check_events.pruned", rows=deleted)
    return deleted
