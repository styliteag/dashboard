"""log_events: aggregated critical log patterns per instance/log.

Revision ID: 031
Revises: 030
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "031"
down_revision: str | None = "030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "log_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("log_name", sa.String(64), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("program", sa.String(64), nullable=False, server_default=""),
        sa.Column("pattern", sa.String(200), nullable=False),
        sa.Column("sample", sa.Text(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("last_ts", sa.String(40), nullable=False, server_default=""),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_log_event_lookup", "log_events", ["instance_id", "log_name"])
    op.create_index("ix_log_event_severity", "log_events", ["severity"])


def downgrade() -> None:
    op.drop_table("log_events")
