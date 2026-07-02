"""firmware update lock per instance

Adds ``firmware_locked`` (BOOL, default false) to ``instances`` — while set,
neither the single-instance firmware update nor the bulk "Update all" action
will run for the instance.

Revision ID: 027
Revises: 026
Create Date: 2026-07-02
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "027"
down_revision: str | None = "026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "instances",
        sa.Column(
            "firmware_locked",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("instances", "firmware_locked")
