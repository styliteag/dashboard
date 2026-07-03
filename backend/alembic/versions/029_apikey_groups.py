"""bind read-only API keys to instance groups.

``apikey_groups`` links an orbit_ API key to the groups whose instances it may
read (Checkmk export / checks endpoints). A key with NO rows here is GLOBAL —
the pre-binding behavior, so existing keys are unaffected. Note the inversion
vs ``user_groups``: a user with no memberships sees nothing.

Revision ID: 029
Revises: 028
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "029"
down_revision: str | None = "028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "apikey_groups",
        sa.Column(
            "apikey_id",
            sa.Integer(),
            sa.ForeignKey("api_keys.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "group_id",
            sa.Integer(),
            sa.ForeignKey("groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )


def downgrade() -> None:
    op.drop_table("apikey_groups")
