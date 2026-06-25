"""per-instance GUI auto-login opt-in (MariaDB).

Adds ``instances.gui_login_enabled`` (bool, default false). When set, the GUI
proxy "Open GUI" replays a WebUI login through the agent so the browser lands
authenticated. The admin credential is provisioned + held agent-side — nothing
is stored on the dashboard. See docs/agent-architecture.md §18.

Revision ID: 006
Revises: 005
Create Date: 2026-06-25
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "instances",
        sa.Column(
            "gui_login_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("instances", "gui_login_enabled")
