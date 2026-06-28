"""logfiles table — recent on-box log snapshots for AI analysis.

Stores the agent's hourly log snapshots (only the newest few per
``(instance_id, name)`` are kept — no long-term history). ``content`` is
MEDIUMTEXT so a ~1 MB snapshot fits; plain TEXT would truncate at 64 KB.

Revision ID: 020
Revises: 019
Create Date: 2026-06-28
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import mysql

from alembic import op

revision: str = "020"
down_revision: str | None = "019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "logfiles",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column(
            "collected_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content", mysql.MEDIUMTEXT(), nullable=False),
    )
    op.create_index("ix_logfile_lookup", "logfiles", ["instance_id", "name", "collected_at"])


def downgrade() -> None:
    op.drop_index("ix_logfile_lookup", table_name="logfiles")
    op.drop_table("logfiles")
