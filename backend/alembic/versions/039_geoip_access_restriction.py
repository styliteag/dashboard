"""GeoIP access restriction: geoip_config table + last-login columns on users.

The dashboard controls root shells on customer firewalls; as an extra layer
on top of password+MFA, interactive access is geo-restricted (superadmin-managed
country allowlist + CIDR/DynDNS whitelist, docs/geoip-access-restriction.md).
``geoip_config`` is a deliberate single-row table (id=1) OUTSIDE app_settings —
the generic settings routes are admin-gated, this surface is superadmin-only
(DR-G6). ``users.last_login_*`` record IP/country of the last successful login
(set at session mint, DR-G7) for the Users admin page.

DDL is re-runnable (IF NOT EXISTS) — replicas race ``upgrade head`` at boot.

Revision ID: 039
Revises: 038
Create Date: 2026-07-12
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "039"
down_revision: str | None = "038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS geoip_config (
            id INTEGER NOT NULL PRIMARY KEY,
            enabled BOOL NOT NULL DEFAULT false,
            countries TEXT NOT NULL,
            whitelist TEXT NOT NULL,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            updated_by VARCHAR(64) NULL
        )
        """
    )
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45) NULL")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_country VARCHAR(2) NULL")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at DATETIME NULL")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS last_login_at")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS last_login_country")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS last_login_ip")
    op.drop_table("geoip_config")
