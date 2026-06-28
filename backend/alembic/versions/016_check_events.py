"""add check_events (service-check state-change history).

Append-only log of service-check state transitions (OK↔WARN↔CRIT), written by the
agent-push ingest when a re-evaluated check differs from its previous state. A
transition log (one row per change), not periodic snapshots — keeps it tiny. Read
behind the instance alert/check-history view; pruned by ``prune_check_events``.

Revision ID: 016
Revises: 015
Create Date: 2026-06-28
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "check_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ts", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("check_key", sa.String(128), nullable=False),
        sa.Column("old_state", sa.Integer(), nullable=False),
        sa.Column("new_state", sa.Integer(), nullable=False),
        sa.Column("summary", sa.String(255), nullable=False, server_default=""),
    )
    op.create_index("ix_check_event_lookup", "check_events", ["instance_id", "ts"])


def downgrade() -> None:
    op.drop_index("ix_check_event_lookup", table_name="check_events")
    op.drop_table("check_events")
