"""Default instance SSH port 22 (was 9922).

New rows without an explicit ssh_port get 22. Existing instance rows keep
whatever port is already stored — only the column server default changes.

Revision ID: 042
Revises: 041
Create Date: 2026-07-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "042"
down_revision: str | None = "041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "instances",
        "ssh_port",
        existing_type=sa.Integer(),
        server_default="22",
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "instances",
        "ssh_port",
        existing_type=sa.Integer(),
        server_default="9922",
        existing_nullable=False,
    )
