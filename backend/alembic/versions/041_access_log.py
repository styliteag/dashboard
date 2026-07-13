"""Access log: session registry + per-principal request accounting.

ADR docs/access-log.md (DR-AL2/AL3). ``auth_sessions`` is bookkeeping for
login sessions (who is online, real expiry events) — deliberately not an
enforcement table. ``access_stats`` counts EVERY request per (hour,
principal) via upsert — bounded cardinality, flood-proof. ``access_events``
holds sampled per-request rows for the timeline, hard-capped per flush
interval and pruned by time — hence the standalone ts index (batched-delete
rule). Same two-tier design as migration 040 (geoip denials).

Revision ID: 041
Revises: 040
Create Date: 2026-07-14
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "041"
down_revision: str | None = "040"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            sid VARCHAR(32) NOT NULL PRIMARY KEY,
            user_id INT NOT NULL,
            ip VARCHAR(45) NULL,
            created_at DATETIME NOT NULL,
            last_seen_at DATETIME NOT NULL,
            ended_at DATETIME NULL,
            end_reason VARCHAR(16) NULL,
            CONSTRAINT fk_auth_sessions_user
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id ON auth_sessions (user_id)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_auth_sessions_last_seen_at ON auth_sessions (last_seen_at)"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS access_stats (
            bucket DATETIME NOT NULL,
            principal_type VARCHAR(8) NOT NULL,
            principal_key VARCHAR(32) NOT NULL,
            count BIGINT NOT NULL DEFAULT 0,
            last_ip VARCHAR(45) NULL,
            PRIMARY KEY (bucket, principal_type, principal_key)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS access_events (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            ts DATETIME NOT NULL,
            user_id INT NULL,
            ip VARCHAR(45) NOT NULL,
            method VARCHAR(8) NOT NULL,
            path VARCHAR(255) NOT NULL,
            status INT NOT NULL
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_access_events_ts ON access_events (ts)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_access_events_ts ON access_events")
    op.drop_table("access_events")
    op.drop_table("access_stats")
    # MariaDB: drop the FK before the indexes (errors 1091/1553).
    op.execute("ALTER TABLE auth_sessions DROP FOREIGN KEY fk_auth_sessions_user")
    op.execute("DROP INDEX IF EXISTS ix_auth_sessions_user_id ON auth_sessions")
    op.execute("DROP INDEX IF EXISTS ix_auth_sessions_last_seen_at ON auth_sessions")
    op.drop_table("auth_sessions")
