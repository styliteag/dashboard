"""Add agent_mode and agent_token to instances.

Revision ID: 005
Revises: 004
Create Date: 2026-04-17
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "instances",
        sa.Column("agent_mode", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "instances",
        sa.Column("agent_token", sa.String(128), nullable=True, unique=True),
    )
    op.add_column(
        "instances",
        sa.Column("agent_last_seen", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("instances", "agent_last_seen")
    op.drop_column("instances", "agent_token")
    op.drop_column("instances", "agent_mode")
