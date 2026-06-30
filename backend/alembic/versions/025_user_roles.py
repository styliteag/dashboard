"""replace users.is_admin with a three-value role column.

Fixed taxonomy ``admin`` | ``user`` | ``view_only`` (see ``app.auth.roles``).
Backfills from the old boolean: ``is_admin`` rows become ``admin``, the rest
``user`` (there were no non-admin accounts before this revision, so in practice
the single seeded admin maps to ``admin``). New rows default to least-privilege
``view_only`` — bootstrap and the user-management API set the role explicitly.

Revision ID: 025
Revises: 024
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "025"
down_revision: str | None = "024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("role", sa.String(16), nullable=False, server_default="view_only"),
    )
    op.execute("UPDATE users SET role = CASE WHEN is_admin THEN 'admin' ELSE 'user' END")
    op.drop_column("users", "is_admin")


def downgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.text("1")),
    )
    op.execute("UPDATE users SET is_admin = (role = 'admin')")
    op.drop_column("users", "role")
