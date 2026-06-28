"""add ``enabled`` to notification_routes (per-instance suppress override).

Adds a non-null ``enabled`` flag (default ``true``) to ``notification_routes`` so a
per-instance route can explicitly **switch off** a category that a global route
turns on — flipping routing from Union to per-box override (a per-instance route
wins over the global one; see ``app.notifications.routing``). All existing rows are
global subscriptions and stay ``enabled=true``, so behaviour is unchanged until an
admin sets an off-override.

Revision ID: 019
Revises: 018
Create Date: 2026-06-28
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "019"
down_revision: str | None = "018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "notification_routes",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    # An off-override has no representation once the column is gone — drop those rows
    # so they don't survive as phantom (now-meaningless) per-instance subscriptions.
    op.execute(sa.text("DELETE FROM notification_routes WHERE enabled = 0"))
    op.drop_column("notification_routes", "enabled")
