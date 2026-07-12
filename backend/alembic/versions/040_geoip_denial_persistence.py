"""Persist GeoIP/CrowdSec denial analytics across restarts.

Two-tier design so a scanner can never flood the DB: ``geoip_denial_stats``
aggregates per (day, reason, country) via upsert — bounded by calendar days ×
~4 reasons × ~250 countries, it counts EVERY denial and is the source of
truth for totals. ``geoip_denial_events`` holds individual rows for the
"recent denials" table, hard-capped per flush interval (excess denials are
still counted in the aggregate, just not row-sampled) and pruned by time —
hence the standalone ts index (batched-delete rule).

Revision ID: 040
Revises: 039
Create Date: 2026-07-12
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "040"
down_revision: str | None = "039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS geoip_denial_stats (
            bucket DATE NOT NULL,
            reason VARCHAR(32) NOT NULL,
            country VARCHAR(4) NOT NULL,
            count BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (bucket, reason, country)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS geoip_denial_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            ts DATETIME NOT NULL,
            ip VARCHAR(45) NOT NULL,
            country VARCHAR(4) NULL,
            path VARCHAR(255) NOT NULL,
            reason VARCHAR(32) NOT NULL
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_geoip_denial_events_ts ON geoip_denial_events (ts)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_geoip_denial_events_ts ON geoip_denial_events")
    op.drop_table("geoip_denial_events")
    op.drop_table("geoip_denial_stats")
