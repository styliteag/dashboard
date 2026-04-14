"""Widen metrics.metric column from VARCHAR(64) to VARCHAR(128).

Must drop and recreate the continuous aggregate since Timescale doesn't
allow altering columns referenced by materialized views.

Revision ID: 004
Revises: 003
Create Date: 2026-04-14
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Remove policies and continuous aggregate that depend on the column
    op.execute("SELECT remove_retention_policy('metrics_5m', if_exists => true)")
    op.execute("SELECT remove_continuous_aggregate_policy('metrics_5m', if_not_exists => true)")
    op.execute("DROP MATERIALIZED VIEW IF EXISTS metrics_5m")

    # Now safe to alter
    op.alter_column("metrics", "metric", type_=sa.String(128), existing_type=sa.String(64))

    # Recreate continuous aggregate and policies
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
    op.alter_column("metrics", "metric", type_=sa.String(64), existing_type=sa.String(128))
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
