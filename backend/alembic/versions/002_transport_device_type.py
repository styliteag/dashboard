"""split agent_mode into transport + device_type (MariaDB).

Replaces the boolean ``instances.agent_mode`` with two string columns:
``transport`` (direct|push|relay) and ``device_type`` (opnsense|pfsense|…).
Existing agent-mode rows become transport='push'; everything else 'direct'.
All existing devices are OPNsense, so device_type backfills to 'opnsense'.

See docs/agent-architecture.md (DR-1).

Revision ID: 002
Revises: 001
Create Date: 2026-06-23
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "instances",
        sa.Column(
            "transport",
            sa.String(16),
            nullable=False,
            server_default=sa.text("'direct'"),
        ),
    )
    op.add_column(
        "instances",
        sa.Column(
            "device_type",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'opnsense'"),
        ),
    )
    # Backfill: agent-mode instances become push transport.
    op.execute("UPDATE instances SET transport = 'push' WHERE agent_mode = 1")
    op.drop_column("instances", "agent_mode")


def downgrade() -> None:
    op.add_column(
        "instances",
        sa.Column(
            "agent_mode",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.execute("UPDATE instances SET agent_mode = 1 WHERE transport = 'push'")
    op.drop_column("instances", "device_type")
    op.drop_column("instances", "transport")
