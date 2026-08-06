defmodule Orbit.Repo.Migrations.FreeSlugOnSoftDelete do
  @moduledoc """
  Make soft delete actually free the slug — the generated-column contract
  the name already follows.

  Regression: `uq_instances_slug` was a UNIQUE on the RAW `slug` column;
  only `name` got the `*_active_key` generated-column treatment in the
  baseline. A soft-deleted instance therefore held its slug forever:
  recreating a box under its old name passed every app-side check (they
  exclude deleted rows), then hit the DB constraint and surfaced as
  "instance name or slug already exists" with no visible row explaining
  why (live incident: Bonis-Prox1 on the pro dev stack, 2026-08-06).

  Same shape as `name_active_key`: NULL while deleted, so any number of
  tombstones may share a slug and MariaDB's unique ignores them (multiple
  NULLs allowed), while active rows stay unique. Safe on existing data:
  every active slug is unique under the old constraint already.

  Raw SQL with IF (NOT) EXISTS — replicas race `migrate` at boot, DDL must
  be re-runnable (the baseline's contract).
  """

  use Ecto.Migration

  def up do
    execute("""
    ALTER TABLE `instances`
      ADD COLUMN IF NOT EXISTS `slug_active_key` varchar(63)
        GENERATED ALWAYS AS (CASE WHEN `deleted_at` IS NULL THEN `slug` END) STORED
    """)

    execute("""
    ALTER TABLE `instances`
      ADD UNIQUE INDEX IF NOT EXISTS `uq_instances_slug_active` (`slug_active_key`)
    """)

    execute("ALTER TABLE `instances` DROP INDEX IF EXISTS `uq_instances_slug`")
  end

  def down do
    # Restoring the raw unique fails if tombstones share a slug with an
    # active row — that data state is exactly what `up` exists to allow, so
    # a real downgrade may need those tombstones hard-deleted first.
    execute("""
    ALTER TABLE `instances` ADD UNIQUE INDEX IF NOT EXISTS `uq_instances_slug` (`slug`)
    """)

    execute("ALTER TABLE `instances` DROP INDEX IF EXISTS `uq_instances_slug_active`")
    execute("ALTER TABLE `instances` DROP COLUMN IF EXISTS `slug_active_key`")
  end
end
