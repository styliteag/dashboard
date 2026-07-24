defmodule Orbit.Repo.Migrations.AddMetricsRollupTiers do
  @moduledoc """
  Rollup tiers for the metrics time-series — `metrics_5m` (5-minute buckets)
  and `metrics_1h` (hourly buckets), cascaded by `Orbit.Metrics.Rollup`:
  raw → 5m → 1h. Charts at 24h/7d read the 5m tier, 30d and the new long
  ranges read the 1h tier; raw retention can then drop without losing chart
  history (a 5m row is ~8.6x cheaper than the raw rows it summarizes,
  measured on the dev fleet; an hourly row 12x cheaper again).

  Deliberate reversal of the old python-era decision that dropped
  `metrics_5m` (alembic migration 008, "bucket raw on the fly"): on-the-fly
  bucketing scans the raw window per chart and caps affordable retention at
  ~30 days. The new tables store sum/min/max/count — NOT avg — so buckets
  cascade with correct weighting (avg-of-avgs overweights sparse buckets)
  and min/max survive for later band charts (today's on-the-fly avg()
  flattens every spike at 30d).

  PK `(instance_id, metric, ts)` is the exact chart access path; the
  standalone ts index is the batched-prune path (house rule: every
  time-pruned table needs one — gap-lock incident). Raw SQL with
  IF (NOT) EXISTS: replicas race `migrate` at boot, DDL must be re-runnable
  (the baseline's contract).
  """

  use Ecto.Migration

  def up do
    for table <- ["metrics_5m", "metrics_1h"] do
      execute("""
      CREATE TABLE IF NOT EXISTS `#{table}` (
        `instance_id` int(11) NOT NULL,
        `metric` varchar(128) NOT NULL,
        `ts` datetime NOT NULL,
        `value_sum` double NOT NULL,
        `value_min` double NOT NULL,
        `value_max` double NOT NULL,
        `sample_count` int(11) NOT NULL,
        PRIMARY KEY (`instance_id`,`metric`,`ts`),
        KEY `ix_#{table}_ts` (`ts`),
        CONSTRAINT `#{table}_ibfk_1` FOREIGN KEY (`instance_id`)
          REFERENCES `instances` (`id`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci
      """)
    end
  end

  def down do
    # DROP TABLE removes the FK with it — no separate drop-FK-before-index
    # dance needed here (that trap applies to ALTERs on surviving tables).
    execute("DROP TABLE IF EXISTS `metrics_1h`")
    execute("DROP TABLE IF EXISTS `metrics_5m`")
  end
end
