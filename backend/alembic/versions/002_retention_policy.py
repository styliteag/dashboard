"""Add Timescale retention policy and continuous aggregate for metrics.

Revision ID: 002
Revises: 001
Create Date: 2026-04-12
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop raw data older than 30 days (US-7.3).
    op.execute(
        "SELECT add_retention_policy('metrics', INTERVAL '30 days', if_not_exists => true)"
    )

    # Continuous aggregate: 5-minute averages kept for 365 days.
    op.execute("""
        CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_5m
        WITH (timescaledb.continuous) AS
        SELECT
            instance_id,
            time_bucket('5 minutes', ts) AS bucket,
            metric,
            avg(value) AS value
        FROM metrics
        GROUP BY instance_id, bucket, metric
        WITH NO DATA
    """)

    op.execute(
        "SELECT add_continuous_aggregate_policy('metrics_5m', "
        "start_offset => INTERVAL '1 hour', "
        "end_offset => INTERVAL '5 minutes', "
        "schedule_interval => INTERVAL '5 minutes', "
        "if_not_exists => true)"
    )

    op.execute(
        "SELECT add_retention_policy('metrics_5m', INTERVAL '365 days', if_not_exists => true)"
    )


def downgrade() -> None:
    op.execute("SELECT remove_retention_policy('metrics_5m', if_exists => true)")
    op.execute("SELECT remove_continuous_aggregate_policy('metrics_5m', if_not_exists => true)")
    op.execute("DROP MATERIALIZED VIEW IF EXISTS metrics_5m")
    op.execute("SELECT remove_retention_policy('metrics', if_exists => true)")
