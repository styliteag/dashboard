"""per-group notification-channel targets.

``group_channels`` stores one Fernet-encrypted JSON config per (group,
channel). A configured row REPLACES the global channel target for that
group's instances; absence = global fallback. Selection-rule routing and the
global mute toggles stay global.

MariaDB note for future editors: the ``group_id`` FK piggybacks on
``uq_group_channel``'s leading column as its supporting index — never drop
that unique constraint while the FK exists (drop the FK first; see the 028
downgrade lesson).

Revision ID: 030
Revises: 029
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "030"
down_revision: str | None = "029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "group_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "group_id",
            sa.Integer(),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("config_enc", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("group_id", "channel", name="uq_group_channel"),
    )


def downgrade() -> None:
    op.drop_table("group_channels")
