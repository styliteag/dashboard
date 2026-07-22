defmodule Orbit.Repo.Migrations.AddMetricsMetricTsIndex do
  @moduledoc """
  Covering index for fleet-wide per-metric reads — `Metrics.push_rate/1`
  filters `metric = 'cpu.total'` over a time window with no instance_id, so
  the only usable index was `ix_metrics_ts`: every metric row in the window
  was scanned and ~97% discarded (a push writes ~30+ rows, one is cpu.total).
  On the 70-box fleet that made every /hub mount and its 10s refresh scan
  six figures of rows. `(metric, ts)` turns it into a range scan over
  exactly the counted rows.

  Raw SQL with IF (NOT) EXISTS: replicas race `migrate` at boot, so DDL must
  be re-runnable (the baseline's contract). InnoDB builds the index INPLACE
  without blocking writes; on a large prod metrics table the first boot
  after this ships simply takes a little longer.
  """

  use Ecto.Migration

  def up do
    execute("CREATE INDEX IF NOT EXISTS ix_metrics_metric_ts ON metrics (metric, ts)")
  end

  def down do
    execute("DROP INDEX IF EXISTS ix_metrics_metric_ts ON metrics")
  end
end
