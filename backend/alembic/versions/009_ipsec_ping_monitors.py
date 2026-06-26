"""add ipsec_ping_monitors (per-Phase-2 connectivity probe).

Stores an optional (source, destination) ping probe per IPsec child SA so the
agent can verify a Phase 2 actually passes traffic, not just that the SA is
INSTALLED. Keyed by (instance_id, tunnel_id, child_name); selectors are cached
for display + a stable fallback match when OPNsense regenerates child UUIDs.

Revision ID: 009
Revises: 008
Create Date: 2026-06-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ipsec_ping_monitors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("tunnel_id", sa.String(128), nullable=False),
        sa.Column("child_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("local_ts", sa.String(255), nullable=False, server_default=""),
        sa.Column("remote_ts", sa.String(255), nullable=False, server_default=""),
        sa.Column("description", sa.String(255), nullable=False, server_default=""),
        sa.Column("source", sa.String(64), nullable=False, server_default=""),
        sa.Column("destination", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("ping_count", sa.Integer(), nullable=False, server_default="3"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("instance_id", "tunnel_id", "child_name", name="uq_ipsec_ping_monitor"),
    )


def downgrade() -> None:
    op.drop_table("ipsec_ping_monitors")
