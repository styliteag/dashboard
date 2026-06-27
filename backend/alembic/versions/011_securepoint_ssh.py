"""add per-instance SSH enrichment columns (Securepoint).

Opt-in SSH path that runs ``swanctl --raw`` on the box for the rich IPsec data
(IKE cookies, ESP SPIs, byte counters) the spcgi API doesn't expose. The private
key is per-instance and Fernet-encrypted (like ``api_secret_enc``).

Revision ID: 011
Revises: 010
Create Date: 2026-06-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "011"
down_revision: str | None = "010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "instances",
        sa.Column("ssh_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "instances",
        sa.Column("ssh_port", sa.Integer(), nullable=False, server_default="9922"),
    )
    op.add_column(
        "instances",
        sa.Column("ssh_user", sa.String(64), nullable=False, server_default="root"),
    )
    op.add_column("instances", sa.Column("ssh_key_enc", sa.LargeBinary(), nullable=True))
    op.add_column("instances", sa.Column("ssh_host_key", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("instances", "ssh_host_key")
    op.drop_column("instances", "ssh_key_enc")
    op.drop_column("instances", "ssh_user")
    op.drop_column("instances", "ssh_port")
    op.drop_column("instances", "ssh_enabled")
