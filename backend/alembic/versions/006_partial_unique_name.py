"""Replace unique constraint on instances.name with a partial unique index
that only applies to non-deleted instances.

Revision ID: 006
Revises: 005
Create Date: 2026-04-17
"""
from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop the old unique constraint
    op.drop_constraint("instances_name_key", "instances", type_="unique")
    # Create a partial unique index: name must be unique only among non-deleted instances
    op.execute(
        "CREATE UNIQUE INDEX uq_instances_name_active ON instances (name) "
        "WHERE deleted_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_instances_name_active")
    op.create_unique_constraint("instances_name_key", "instances", ["name"])
