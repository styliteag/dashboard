"""ipsec/check events: standalone ts indexes for the retention prunes.

Same flaw ``ix_metrics_ts`` (033) fixed on ``metrics``: ``ts`` sits behind other
index columns (``ix_ipsec_event_lookup``, ``ix_check_event_lookup``), so the
batched ``DELETE ... WHERE ts < cutoff ORDER BY ts LIMIT n`` in ``_prune_before``
full-scans and next-key-locks the whole table. Both tables are tiny transition
logs today, so this is preventive — the locks only start hurting once a fleet
with flapping tunnels/checks grows them. ``IF NOT EXISTS`` keeps the migration
re-runnable (multi-replica boots race ``alembic upgrade head``; see 033).

Revision ID: 034
Revises: 033
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "034"
down_revision: str | None = "033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE INDEX IF NOT EXISTS ix_ipsec_events_ts ON ipsec_tunnel_events (ts)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_check_events_ts ON check_events (ts)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_ipsec_events_ts ON ipsec_tunnel_events")
    op.execute("DROP INDEX IF EXISTS ix_check_events_ts ON check_events")
