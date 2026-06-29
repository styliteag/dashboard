"""add connectivity_monitors (standalone, tunnel-independent ping probe).

Stores a (source, destination) ping probe per instance that is NOT tied to an
IPsec tunnel. The agent pings it on the firewall each push cycle and reports
ok/fail/error keyed by the row id, so the check key ``connectivity:<id>`` stays
stable across renames. Unique per (instance_id, name).

Revision ID: 022
Revises: 021
Create Date: 2026-06-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "022"
down_revision: str | None = "021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "connectivity_monitors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(128), nullable=False),
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
        sa.UniqueConstraint("instance_id", "name", name="uq_connectivity_monitor"),
    )


def downgrade() -> None:
    op.drop_table("connectivity_monitors")
