"""metrics: add standalone ts index for the retention prune.

The ``metrics`` PK is ``(instance_id, ts, metric)``, so ``ts`` is not seekable on
its own. The hourly retention prune (``DELETE FROM metrics WHERE ts < cutoff``)
therefore full-scanned the clustered index, taking next-key/gap locks across every
instance's rows under REPEATABLE READ and blocking concurrent poll/push INSERTs
until they hit the 50s lock-wait timeout (surfacing as boxes flipping offline with
"Lock wait timeout exceeded"). A standalone ``ts`` index lets the prune range-scan
only the old rows, leaving the recent range where fresh inserts land unlocked.

Revision ID: 033
Revises: 032
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "033"
down_revision: str | None = "032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_metrics_ts", "metrics", ["ts"])


def downgrade() -> None:
    op.drop_index("ix_metrics_ts", table_name="metrics")
