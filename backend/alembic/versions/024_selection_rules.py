"""unify service selection into selection_rules.

Replaces ``checkmk_export_exclusions`` (opt-out, export-only) and
``notification_routes`` (opt-in, channel-only) with a single ``selection_rules``
table shared by the Checkmk export *and* the notification channels.

A rule is ``(consumer, instance_id | None, selector, mode)``: ``consumer`` is
``checkmk`` or a channel; ``selector`` is a category token or a full check key;
``mode`` is ``include`` / ``exclude``. The base default is OFF for every consumer
and **no rows are seeded** — a fresh install selects nothing until an admin opts
in. (Existing rows in the dropped tables are intentionally discarded.)

Revision ID: 024
Revises: 023
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "024"
down_revision: str | None = "023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("checkmk_export_exclusions")
    op.drop_table("notification_routes")
    op.create_table(
        "selection_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("consumer", sa.String(32), nullable=False, index=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=True,
            index=True,
        ),
        sa.Column("selector", sa.String(255), nullable=False),
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("consumer", "instance_id", "selector", name="uq_selection_rule"),
    )


def downgrade() -> None:
    op.drop_table("selection_rules")
    # Recreate the two tables as they stood at revision 023 (data is not restored).
    op.create_table(
        "checkmk_export_exclusions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=True,
            index=True,
        ),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("instance_id", "target", name="uq_checkmk_exclusion"),
    )
    op.create_table(
        "notification_routes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=True,
            index=True,
        ),
        sa.Column("channel", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("instance_id", "channel", "category", name="uq_notification_route"),
    )
