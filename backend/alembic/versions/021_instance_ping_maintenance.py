"""out-of-band reachability probe + maintenance flag per instance.

Adds two columns to ``instances``:

* ``ping_url`` (VARCHAR, nullable) — admin-supplied URL/host the dashboard probes
  directly via ICMP + HTTP, independent of the agent. NULL = no probe.
* ``maintenance`` (BOOL, default false) — while set, every check for the instance
  is capped at WARN (yellow, never red); auto-cleared on the next healthy report.

Revision ID: 021
Revises: 020
Create Date: 2026-06-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "021"
down_revision: str | None = "020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("instances", sa.Column("ping_url", sa.String(length=512), nullable=True))
    op.add_column(
        "instances",
        sa.Column(
            "maintenance",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("instances", "maintenance")
    op.drop_column("instances", "ping_url")
