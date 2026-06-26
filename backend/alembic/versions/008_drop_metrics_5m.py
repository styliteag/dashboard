"""drop the unused metrics_5m rollup table (MariaDB).

The 5-minute rollup table was never read: ``read_metrics`` always buckets from
the raw ``metrics`` table on the fly (every chart range, incl. 30d), and nothing
else SELECTs ``metrics_5m``. The rollup job therefore wrote a table with zero
readers while consuming the bulk of the DB footprint (365-day retention). Drop
the table; the ``rollup_5m`` job and ``metrics_5m_retention_days`` setting are
removed in the same change.

Downgrade recreates the empty table (schema only — rolled-up data is not
reconstructable).

Revision ID: 008
Revises: 007
Create Date: 2026-06-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("metrics_5m")


def downgrade() -> None:
    op.create_table(
        "metrics_5m",
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("bucket", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metric", sa.String(128), nullable=False),
        sa.Column("value", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("instance_id", "bucket", "metric"),
    )
