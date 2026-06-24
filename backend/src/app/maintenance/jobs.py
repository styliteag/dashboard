"""Scheduled metrics maintenance — replaces TimescaleDB retention + continuous
aggregate after the move to MariaDB (see memory todo_apscheduler_jobs).

- rollup_5m: avg(value) of raw ``metrics`` into ``metrics_5m`` per
  (instance_id, 5-min bucket, metric); idempotent upsert over completed buckets.
- prune_metrics: delete raw rows older than ``metrics_retention_days`` and 5-min
  rows older than ``metrics_5m_retention_days``.

Both are idempotent and run off the shared AsyncSession factory.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import text

from app.config import get_settings
from app.db.base import get_sessionmaker

log = structlog.get_logger("app.maintenance")

_BUCKET_SECONDS = 300  # 5 minutes

# Roll up only completed buckets (ts strictly before the current bucket's start);
# re-process the last 15 min each run so a missed run self-heals (upsert).
_ROLLUP_SQL = text(
    f"""
    INSERT INTO metrics_5m (instance_id, bucket, metric, value)
    SELECT instance_id,
           FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV {_BUCKET_SECONDS} * {_BUCKET_SECONDS}) AS bucket,
           metric,
           AVG(value) AS value
    FROM metrics
    WHERE ts >= NOW() - INTERVAL 15 MINUTE
      AND ts <  FROM_UNIXTIME(UNIX_TIMESTAMP(NOW()) DIV {_BUCKET_SECONDS} * {_BUCKET_SECONDS})
    GROUP BY instance_id,
             FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV {_BUCKET_SECONDS} * {_BUCKET_SECONDS}),
             metric
    ON DUPLICATE KEY UPDATE value = VALUES(value)
    """
)


async def rollup_5m() -> int:
    """Upsert recent raw metrics into the 5-minute rollup. Returns rows affected."""
    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        result = await session.execute(_ROLLUP_SQL)
        await session.commit()
    rows = result.rowcount or 0
    log.debug("metrics.rollup", rows=rows)
    return rows


async def prune_metrics() -> tuple[int, int]:
    """Delete metrics older than the retention windows. Returns (raw, agg) deleted."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    raw_cutoff = now - timedelta(days=settings.metrics_retention_days)
    agg_cutoff = now - timedelta(days=settings.metrics_5m_retention_days)

    sessionmaker = get_sessionmaker()
    async with sessionmaker() as session:
        r_raw = await session.execute(text("DELETE FROM metrics WHERE ts < :c"), {"c": raw_cutoff})
        r_agg = await session.execute(
            text("DELETE FROM metrics_5m WHERE bucket < :c"), {"c": agg_cutoff}
        )
        await session.commit()
    raw, agg = r_raw.rowcount or 0, r_agg.rowcount or 0
    if raw or agg:
        log.info("metrics.pruned", raw=raw, agg=agg)
    return raw, agg
