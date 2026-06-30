"""mandatory 2FA: TOTP columns, bootstrap/disabled flags, webauthn credentials.

Adds the per-user 2FA state (``totp_secret_enc``, ``totp_enabled``), the bootstrap
seed marker and the ``disabled`` flag that ``DASH_ADMIN_DISABLED`` drives, plus the
``webauthn_credentials`` table for passkeys. The pre-existing seeded ``admin`` row
is marked ``is_bootstrap`` so the env-driven lifecycle recognises it; it keeps
``totp_enabled=False`` and is forced to enroll on its next login.

Revision ID: 026
Revises: 025
Create Date: 2026-06-30
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "026"
down_revision: str | None = "025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret_enc", sa.LargeBinary(), nullable=True))
    op.add_column(
        "users",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "users",
        sa.Column("is_bootstrap", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "users",
        sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # The single env-seeded admin becomes the recognised bootstrap account.
    op.execute("UPDATE users SET is_bootstrap = TRUE WHERE username = 'admin'")

    op.create_table(
        "webauthn_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("credential_id", sa.String(255), nullable=False, unique=True),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("name", sa.String(128), nullable=True),
        sa.Column("transports", sa.String(255), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("webauthn_credentials")
    op.drop_column("users", "disabled")
    op.drop_column("users", "is_bootstrap")
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret_enc")
