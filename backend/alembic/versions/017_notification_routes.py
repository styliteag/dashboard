"""add notification_routes (per-channel alert-category subscriptions).

Each row subscribes one notification ``channel`` (mattermost/telegram/email) to one
alert ``category`` (``availability`` or a Checkmk check category). Presence = the
channel receives that category (opt-in). The three ``availability`` rows are seeded
so instance offline/recovered alerts keep working on a fresh install without any
configuration; the noisier check categories are opt-in via the Settings UI.

Revision ID: 017
Revises: 016
Create Date: 2026-06-28
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "017"
down_revision: str | None = "016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SEED_CHANNELS = ("mattermost", "telegram", "email")


def upgrade() -> None:
    op.create_table(
        "notification_routes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("channel", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("channel", "category", name="uq_notification_route"),
    )
    routes = sa.table(
        "notification_routes",
        sa.column("channel", sa.String),
        sa.column("category", sa.String),
    )
    op.bulk_insert(
        routes,
        [{"channel": c, "category": "availability"} for c in _SEED_CHANNELS],
    )


def downgrade() -> None:
    op.drop_table("notification_routes")
