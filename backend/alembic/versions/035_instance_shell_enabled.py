"""per-instance browser-terminal opt-in + backfill from Auto-Login (MariaDB).

Adds ``instances.shell_enabled`` (bool, default false). When set — and the global
``DASH_SHELL_ENABLED`` is also on — the dashboard offers a browser terminal to a
root PTY on the box, tunneled through the agent. Arbitrary root RCE, so it is a
deliberate per-instance opt-in. See docs/agent-architecture.md §22.

Backfill: instances that already have WebUI Auto-Login enabled
(``gui_login_enabled``) are trusted for a full authenticated GUI bridge, so they
get the terminal turned on too. New instances still default to off.

The add-column step is guarded (skipped when the column already exists) so the
migration is safe to re-run after a partial apply — MariaDB implicitly commits
DDL, so an interrupted first run can leave the column present at revision 034.

Revision ID: 035
Revises: 034
Create Date: 2026-07-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "035"
down_revision: str | None = "034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("instances")}
    if "shell_enabled" not in columns:
        op.add_column(
            "instances",
            sa.Column(
                "shell_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
    # One-time backfill: mirror the Auto-Login trust decision onto the terminal.
    op.execute("UPDATE instances SET shell_enabled = true WHERE gui_login_enabled = true")


def downgrade() -> None:
    op.drop_column("instances", "shell_enabled")
