"""config_backups table — versioned, encrypted config.xml snapshots.

The agent pushes config.xml when it changes; the store keeps the newest
``KEEP_PER_INSTANCE`` versions per instance for diffing and disaster-recovery
download. ``content_enc`` holds the Fernet token of the XML (config.xml carries
secrets — never plaintext at rest); MEDIUMBLOB so multi-MB configs fit.

Revision ID: 036
Revises: 035
Create Date: 2026-07-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import mysql

from alembic import op

revision: str = "036"
down_revision: str | None = "035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "config_backups",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "collected_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source", sa.String(16), nullable=False, server_default="agent"),
        sa.Column("content_enc", mysql.MEDIUMBLOB(), nullable=False),
    )
    op.create_index("ix_config_backup_lookup", "config_backups", ["instance_id", "collected_at"])


def downgrade() -> None:
    op.drop_index("ix_config_backup_lookup", table_name="config_backups")
    op.drop_table("config_backups")
