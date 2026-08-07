defmodule Orbit.Repo.Migrations.AddAlertStates do
  @moduledoc """
  Alert lifecycle state (docs/alert-lifecycle.md DR-LC2): one row per
  alert occurrence, identified by (instance_id, check_key) while
  unresolved. Written ONLY by the reconciler (single writer — the
  scheduler GenServer runs jobs sequentially) and by ack/snooze events;
  the computed check surfaces stay untouched (DR-LC3).

  MariaDB has no partial unique indexes, so "unique while unresolved" is
  the reconciler's single-writer invariant, not a constraint. resolved_at
  gets its own index: rows are pruned by time (batched oldest-first, the
  gap-lock rule) and the reconciler filters on it constantly.

  Raw SQL with IF (NOT) EXISTS — replicas race `migrate` at boot, DDL
  must be re-runnable (the baseline's contract).
  """

  use Ecto.Migration

  def up do
    execute("""
    CREATE TABLE IF NOT EXISTS `alert_states` (
      `id` bigint unsigned NOT NULL AUTO_INCREMENT,
      `instance_id` int NOT NULL,
      `check_key` varchar(255) NOT NULL,
      `severity` smallint NOT NULL,
      `first_seen_at` datetime NOT NULL,
      `last_seen_at` datetime NOT NULL,
      `acked_by` varchar(255) NULL,
      `acked_at` datetime NULL,
      `snoozed_until` datetime NULL,
      `resolved_at` datetime NULL,
      PRIMARY KEY (`id`),
      KEY `ix_alert_states_instance_key` (`instance_id`, `check_key`),
      KEY `ix_alert_states_resolved_at` (`resolved_at`)
    )
    """)
  end

  def down do
    execute("DROP TABLE IF EXISTS `alert_states`")
  end
end
