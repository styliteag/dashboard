"""one-time agent enrollment codes (MariaDB).

Adds ``enrollment_codes`` backing /api/agent/enroll — the admin mints a
short-lived, single-use code for an instance and the agent trades it for that
instance's agent_token (so no token is pasted by hand). See §16 chunk C2.

Revision ID: 005
Revises: 004
Create Date: 2026-06-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "enrollment_codes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("code_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_enrollment_codes_code_hash", "enrollment_codes", ["code_hash"])


def downgrade() -> None:
    op.drop_index("ix_enrollment_codes_code_hash", table_name="enrollment_codes")
    op.drop_table("enrollment_codes")
