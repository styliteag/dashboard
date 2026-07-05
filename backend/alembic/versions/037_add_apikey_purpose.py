"""add optional purpose column to api_keys.

Used to separate/t tag read-only API keys by intended consumer in the Settings
UI (e.g. "checkmk" vs "prometheus"). The column is nullable so all existing
keys remain valid (they appear in both tabs for backward compatibility). Auth
and exports do not filter on purpose — it is UI organization only.

Revision ID: 037
Revises: 036
Create Date: 2026-07-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "037"
down_revision: str | None = "036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("purpose", sa.String(32), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("api_keys", "purpose")
