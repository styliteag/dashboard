"""last-known status snapshot per instance (restart persistence, MariaDB).

Adds ``instances.status_snapshot`` (JSON) — the agent hub serializes its
in-memory live-status caches here on every push, and re-hydrates from it at
startup so a backend restart doesn't blank the dashboard. See §16 chunk B.

Revision ID: 004
Revises: 003
Create Date: 2026-06-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("instances", sa.Column("status_snapshot", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("instances", "status_snapshot")
