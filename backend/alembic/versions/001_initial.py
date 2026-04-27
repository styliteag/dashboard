"""initial schema (consolidated baseline).

Tables: users, instances, audit_log, metrics. Metrics promoted to a Timescale
hypertable; metrics_5m continuous aggregate with 30d / 365d retention.

Revision ID: 001
Revises:
Create Date: 2026-04-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE")

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("password_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "instances",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("api_key_enc", sa.LargeBinary(), nullable=False),
        sa.Column("api_secret_enc", sa.LargeBinary(), nullable=False),
        sa.Column("ca_bundle", sa.Text(), nullable=True),
        sa.Column("ssl_verify", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("agent_mode", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("agent_token", sa.String(128), nullable=True, unique=True),
        sa.Column("agent_last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("location", sa.String(255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("tags", postgresql.JSONB(), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_message", sa.Text(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    # Partial unique on name, only among non-deleted rows.
    op.execute(
        "CREATE UNIQUE INDEX uq_instances_name_active ON instances (name) WHERE deleted_at IS NULL"
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(64), nullable=True),
        sa.Column("target_id", sa.String(128), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column("source_ip", sa.String(64), nullable=True),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])

    op.create_table(
        "metrics",
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metric", sa.String(128), nullable=False),
        sa.Column("value", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("instance_id", "ts", "metric"),
    )
    op.execute(
        "SELECT create_hypertable('metrics', 'ts', if_not_exists => TRUE, migrate_data => TRUE)"
    )
    op.execute("SELECT add_retention_policy('metrics', INTERVAL '30 days', if_not_exists => true)")

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
    op.drop_table("metrics")
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_ts", table_name="audit_log")
    op.drop_table("audit_log")
    op.execute("DROP INDEX IF EXISTS uq_instances_name_active")
    op.drop_table("instances")
    op.drop_table("users")
