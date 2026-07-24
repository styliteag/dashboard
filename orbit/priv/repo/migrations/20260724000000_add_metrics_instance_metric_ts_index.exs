defmodule Orbit.Repo.Migrations.AddMetricsInstanceMetricTsIndex do
  @moduledoc """
  Exact-match index for per-instance chart reads — `Metrics.read/3` filters
  `instance_id = ? AND metric = ? AND ts BETWEEN`, and the best existing
  access path was the PK `(instance_id, ts, metric)`: a range scan over the
  instance's whole time window that discards every row belonging to another
  metric. A push writes ~35-48 rows, one matches, so every chart panel read
  ~40x the rows it returned (EXPLAIN on prod, 24h cpu.total: 105,794 rows
  examined for ~2,880 wanted). `(instance_id, metric, ts)` makes the read a
  range scan over exactly the returned rows; storage cost is comparable to
  `ix_metrics_metric_ts` (the key columns are a permutation of the PK, so
  leaf entries carry no extra PK pointer bytes).

  Raw SQL with IF (NOT) EXISTS: replicas race `migrate` at boot, so DDL must
  be re-runnable (the baseline's contract). InnoDB builds the index INPLACE
  without blocking writes, but the build over a large prod metrics table
  stalls boot for minutes — pre-create the index manually in a quiet hour
  (same statement) and this migration no-ops at the next deploy.
  """

  use Ecto.Migration

  def up do
    execute(
      "CREATE INDEX IF NOT EXISTS ix_metrics_instance_metric_ts ON metrics (instance_id, metric, ts)"
    )
  end

  def down do
    execute("DROP INDEX IF EXISTS ix_metrics_instance_metric_ts ON metrics")
  end
end
