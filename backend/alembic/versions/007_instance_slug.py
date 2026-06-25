"""per-instance URL-safe slug for the GUI proxy (MariaDB).

Adds ``instances.slug`` — a DNS label used in the prod GUI-proxy origin
``gui-<slug>.<domain>`` (§18). Existing rows are backfilled from ``name`` via the
shared ``slugify_name`` helper, deduped by appending ``-<id>`` on collision, then
the column is made NOT NULL.

Uniqueness is enforced among *active* instances only — same trick as ``name`` (001):
a STORED generated column ``slug_active_key`` that is NULL when soft-deleted (NULLs
are distinct in a unique index), with a unique index on it. So a soft-deleted row
frees its slug for reuse without mutating the stored value.

Revision ID: 007
Revises: 006
Create Date: 2026-06-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.instances.slug import MAX_SLUG_LEN, slugify_name

revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _unique_slug(name: str, instance_id: int, used: set[str]) -> str:
    """Derive a slug from ``name``, disambiguated with ``-<id>`` if already taken."""
    base = slugify_name(name or "")
    if base not in used:
        return base
    suffixed = f"{base[: MAX_SLUG_LEN - len(str(instance_id)) - 1]}-{instance_id}".strip("-")
    candidate = suffixed or f"fw-{instance_id}"
    while candidate in used:  # pathological; keep it terminating
        candidate = f"{candidate[: MAX_SLUG_LEN - 2]}-x"
    return candidate


def upgrade() -> None:
    op.add_column("instances", sa.Column("slug", sa.String(length=MAX_SLUG_LEN), nullable=True))

    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT id, name, deleted_at FROM instances ORDER BY id")
    ).fetchall()
    # Only active rows share the unique index, so dedupe their slugs; soft-deleted
    # rows get a derived slug too (for display) but don't reserve the name.
    active_used: set[str] = set()
    for row in rows:
        is_active = row.deleted_at is None
        slug = _unique_slug(row.name, row.id, active_used if is_active else set())
        if is_active:
            active_used.add(slug)
        conn.execute(
            sa.text("UPDATE instances SET slug = :slug WHERE id = :id"),
            {"slug": slug, "id": row.id},
        )

    op.alter_column(
        "instances", "slug", existing_type=sa.String(length=MAX_SLUG_LEN), nullable=False
    )
    # Partial unique on slug across non-deleted rows (MariaDB has no partial index):
    # a STORED generated column that is NULL when soft-deleted — same trick as `name`.
    op.execute(
        "ALTER TABLE instances ADD COLUMN slug_active_key VARCHAR(63) "
        "GENERATED ALWAYS AS (CASE WHEN deleted_at IS NULL THEN slug END) STORED"
    )
    op.create_index("uq_instances_slug_active", "instances", ["slug_active_key"], unique=True)


def downgrade() -> None:
    op.drop_index("uq_instances_slug_active", table_name="instances")
    op.drop_column("instances", "slug_active_key")
    op.drop_column("instances", "slug")
