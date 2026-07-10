"""entity_comments table — free-text operator comments on non-DB entities.

Instances already carry a ``notes`` column, but VPN tunnels, certificates and
firmware are ephemeral hub/live data with no DB row to attach a note to, and
connectivity monitors have no comment column. One generic table covers them all:
a comment is keyed by (instance_id, kind, entity_key) where ``kind`` is the
entity family (ipsec | connectivity | firmware | cert) and ``entity_key`` the
family's stable per-instance id (tunnel connection name, monitor id, cert refid;
empty for the per-instance firmware note). Editable from the overviews and the
per-instance tabs (pencil-on-hover UI).

Revision ID: 038
Revises: 037
Create Date: 2026-07-10
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "038"
down_revision: str | None = "037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "entity_comments",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column(
            "instance_id",
            sa.Integer(),
            sa.ForeignKey("instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("entity_key", sa.String(255), nullable=False, server_default=""),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.String(64), nullable=False, server_default=""),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        # Also serves as the FK's index (instance_id is the leftmost column), so no
        # separate ix on instance_id — a standalone one would hit the MariaDB
        # drop-order trap (1553) on downgrade for zero read benefit.
        sa.UniqueConstraint("instance_id", "kind", "entity_key", name="uq_entity_comment"),
    )


def downgrade() -> None:
    op.drop_table("entity_comments")
