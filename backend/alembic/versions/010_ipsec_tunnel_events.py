"""add ipsec_tunnel_events (per-tunnel state-change history).

Append-only log of IPsec tunnel state transitions, written by the agent-push
ingest when a pushed snapshot differs from the previous one: Phase-1 up/down,
Phase-2 installed-count changes, and per-child ping ok/fail. A transition log
(one row per change), not periodic snapshots — keeps it tiny. Read behind the
VPN-overview history popup; pruned by ``prune_ipsec_events``.

Revision ID: 010
Revises: 009
Create Date: 2026-06-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "010"
down_revision: str | None = "009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ipsec_tunnel_events",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tunnel_id", sa.String(128), nullable=False),
        sa.Column("child_name", sa.String(128), nullable=False, server_default=""),
        sa.Column("ts", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("old_value", sa.String(255), nullable=False, server_default=""),
        sa.Column("new_value", sa.String(255), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_ipsec_event_lookup",
        "ipsec_tunnel_events",
        ["instance_id", "tunnel_id", "ts"],
    )


def downgrade() -> None:
    op.drop_index("ix_ipsec_event_lookup", table_name="ipsec_tunnel_events")
    op.drop_table("ipsec_tunnel_events")
