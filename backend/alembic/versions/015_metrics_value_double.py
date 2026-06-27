"""widen metrics.value from single-precision FLOAT to DOUBLE.

A 4-byte FLOAT has a 24-bit mantissa, so integers are exact only up to 2^24
(16,777,216). The iface.*.bytes_rx/tx metrics store raw cumulative byte counters,
which on any box with non-trivial uptime sit far above that — so the stored value
was quantized and per-interval throughput rates (computed by subtracting two
consecutive samples) flatlined at 0 or jumped a whole quantum on low-traffic
interfaces. DOUBLE (53-bit mantissa) is exact for integers up to 2^53.

Note: this rewrites the metrics table (FLOAT -> DOUBLE is a copy ALTER); on a
large table it can take a while and hold a lock. Existing stored values are
preserved as-is (already-quantized values cannot be recovered, but new writes are
full precision).

Revision ID: 015
Revises: 014
Create Date: 2026-06-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "015"
down_revision: str | None = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "metrics",
        "value",
        existing_type=sa.Float(),
        type_=sa.Double(),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "metrics",
        "value",
        existing_type=sa.Double(),
        type_=sa.Float(),
        existing_nullable=False,
    )
