"""add per-instance poll/push interval override columns.

NULL on either column means "inherit the global default"
(DASH_POLL_INTERVAL_SECONDS / DASH_PUSH_INTERVAL_SECONDS). poll applies to
direct-API devices; push is mirrored to the agent in push mode.

Revision ID: 012
Revises: 011
Create Date: 2026-06-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("instances", sa.Column("poll_interval_seconds", sa.Integer(), nullable=True))
    op.add_column("instances", sa.Column("push_interval_seconds", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("instances", "push_interval_seconds")
    op.drop_column("instances", "poll_interval_seconds")
