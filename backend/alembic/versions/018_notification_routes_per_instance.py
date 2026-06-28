"""add per-instance scope to notification_routes.

Adds a nullable ``instance_id`` FK to ``notification_routes`` so a route can be
*global* (NULL — every instance, the prior behaviour) or scoped to one instance.
The unique key widens from ``(channel, category)`` to ``(instance_id, channel,
category)``. Existing rows keep ``instance_id`` NULL, so all current global
subscriptions (incl. the seeded ``availability`` rows) are preserved unchanged.

Matching is Union (global OR per-instance) — see ``app.notifications.routing``.

Revision ID: 018
Revises: 017
Create Date: 2026-06-28
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "018"
down_revision: str | None = "017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "notification_routes",
        sa.Column("instance_id", sa.Integer(), nullable=True),
    )
    op.create_index("ix_notification_routes_instance_id", "notification_routes", ["instance_id"])
    op.create_foreign_key(
        "fk_notification_routes_instance_id",
        "notification_routes",
        "instances",
        ["instance_id"],
        ["id"],
        ondelete="CASCADE",
    )
    # Widen the unique key so a global and a per-instance route for the same
    # (channel, category) can coexist.
    op.drop_constraint("uq_notification_route", "notification_routes", type_="unique")
    op.create_unique_constraint(
        "uq_notification_route",
        "notification_routes",
        ["instance_id", "channel", "category"],
    )


def downgrade() -> None:
    # Drop any per-instance routes first — they can't be represented once the
    # column is gone, and they'd otherwise collide on the narrowed unique key.
    op.execute(sa.text("DELETE FROM notification_routes WHERE instance_id IS NOT NULL"))
    op.drop_constraint("uq_notification_route", "notification_routes", type_="unique")
    op.create_unique_constraint(
        "uq_notification_route", "notification_routes", ["channel", "category"]
    )
    op.drop_constraint(
        "fk_notification_routes_instance_id", "notification_routes", type_="foreignkey"
    )
    op.drop_index("ix_notification_routes_instance_id", table_name="notification_routes")
    op.drop_column("notification_routes", "instance_id")
