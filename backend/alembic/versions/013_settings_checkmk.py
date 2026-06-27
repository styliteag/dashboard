"""settings: Checkmk export exclusions + revealable API keys.

Adds the ``checkmk_export_exclusions`` table (rules that hide service checks from
the Checkmk export only) and two columns on ``api_keys`` so a key can be
re-displayed in the Settings UI: ``revealable`` (flag) + ``key_enc`` (Fernet
ciphertext of the full token, NULL for show-once keys).

Revision ID: 013
Revises: 012
Create Date: 2026-06-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "013"
down_revision: str | None = "012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "checkmk_export_exclusions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("instance_id", "target", name="uq_checkmk_exclusion"),
    )
    op.create_index(
        "ix_checkmk_export_exclusions_instance_id",
        "checkmk_export_exclusions",
        ["instance_id"],
    )
    op.add_column(
        "api_keys",
        sa.Column("revealable", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("api_keys", sa.Column("key_enc", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("api_keys", "key_enc")
    op.drop_column("api_keys", "revealable")
    op.drop_index(
        "ix_checkmk_export_exclusions_instance_id",
        table_name="checkmk_export_exclusions",
    )
    op.drop_table("checkmk_export_exclusions")
