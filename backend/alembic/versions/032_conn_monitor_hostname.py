"""connectivity_monitors.destination: allow hostnames (64 → 253 chars).

Revision ID: 032
Revises: 031
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "032"
down_revision: str | None = "031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "connectivity_monitors",
        "destination",
        existing_type=sa.String(64),
        type_=sa.String(253),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "connectivity_monitors",
        "destination",
        existing_type=sa.String(253),
        type_=sa.String(64),
        existing_nullable=False,
    )
