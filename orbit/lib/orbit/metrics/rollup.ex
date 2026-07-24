defmodule Orbit.Metrics.Rollup do
  @moduledoc """
  Cascaded metric rollups: `metrics` → `metrics_5m` → `metrics_1h`.

  Each tier stores `value_sum / value_min / value_max / sample_count` per
  `(instance_id, metric, bucket)` — sum+count instead of avg, so the next
  tier aggregates with correct weighting (`SUM(sum)/SUM(count)`; avg-of-avgs
  overweights buckets where the agent was only briefly online) and min/max
  survive the cascade (a reboot's uptime dip or a pf.states spike stays
  visible a year later).

  Incremental with a self-healing watermark: each run re-aggregates from the
  newest existing bucket (late rows in that bucket are folded in via
  ON DUPLICATE KEY UPDATE — the statement is idempotent per bucket) up to the
  last COMPLETED bucket, in aligned chunks. Chunks bound transaction size;
  `@max_chunks` bounds a single run, so the post-upgrade backfill of a large
  raw table proceeds across scheduler ticks instead of one monster statement.
  Bucket alignment of every chunk boundary is load-bearing: a chunk that
  split a bucket would write partial aggregates that ON DUPLICATE KEY then
  OVERWRITES (not merges) on the next run.

  Cold start seeds from the source's oldest row, so an upgrade backfills the
  whole existing raw window into both tiers. `UNIX_TIMESTAMP`/`FROM_UNIXTIME`
  bucketing is safe only because every connection is UTC-pinned in
  `Orbit.Repo.init/2` (same contract as `Orbit.Metrics`).
  """

  require Logger

  @tier_5m %{
    table: "metrics_5m",
    source: "metrics",
    bucket: 300,
    chunk: 3_600,
    max_chunks: 24,
    select: "SUM(value), MIN(value), MAX(value), COUNT(*)"
  }

  @tier_1h %{
    table: "metrics_1h",
    source: "metrics_5m",
    bucket: 3_600,
    chunk: 86_400,
    max_chunks: 20,
    select: "SUM(value_sum), MIN(value_min), MAX(value_max), SUM(sample_count)"
  }

  @doc "Roll raw metrics into 5-minute buckets. Returns affected row count."
  def run_5m, do: run(@tier_5m)

  @doc "Roll 5-minute buckets into hourly buckets. Returns affected row count."
  def run_1h, do: run(@tier_1h)

  @doc "The tier specs, keyed by table — for tests pinning the cascade shape."
  def tiers, do: %{"metrics_5m" => @tier_5m, "metrics_1h" => @tier_1h}

  defp run(tier) do
    end_bound = floor_bucket(System.os_time(:second), tier.bucket)

    fresh =
      case scalar(watermark_sql(tier)) do
        nil ->
          []

        next ->
          chunk_ranges(floor_bucket(next, tier.bucket), end_bound, tier.chunk, tier.max_chunks)
      end

    affected =
      (redo_chunk(tier, end_bound) ++ fresh)
      |> Enum.reduce(0, fn {from, to}, acc ->
        %{num_rows: n} = Orbit.Repo.query!(upsert_sql(tier), [naive(from), naive(to)])
        acc + n
      end)

    if fresh != [],
      do: Logger.info("metrics.rollup table=#{tier.table} affected=#{affected}")

    affected
  end

  # The newest existing bucket, re-aggregated on every run so source rows
  # that arrived after the last run fold in via ON DUPLICATE KEY. This is a
  # SEPARATE chunk from the fresh-ground scan on purpose — see watermark_sql.
  defp redo_chunk(%{table: table, bucket: bucket}, end_bound) do
    case scalar("SELECT UNIX_TIMESTAMP(MAX(ts)) FROM #{table}") do
      nil -> []
      newest -> for to <- [min(newest + bucket, end_bound)], to > newest, do: {newest, to}
    end
  end

  @doc """
  Fresh-ground watermark: the source's next row at or after the END of the
  target's newest bucket (`MAX(ts) + bucket`), floored by the caller. Two
  wrong anchors preceded this one (both found live on the dev DB, where the
  stack is off for days at a time — in prod any outage longer than a run's
  span reproduces it):

    1. Anchor = target MAX(ts) alone: a source gap longer than
       max_chunks * chunk meant every run re-derived the same start,
       aggregated only empty chunks, and never advanced — stalled forever.
    2. Anchor = source MIN(ts >= MAX(ts)): when the source data stops
       MID-bucket right before the gap, the newest bucket's own rows satisfy
       `>= MAX(ts)` on every run, so the watermark re-anchored on them and
       still never crossed the gap.

  Asking for the first row at/past the newest bucket's END cannot see the
  newest bucket's own rows, so a gap of any length is skipped in one indexed
  MIN lookup; the newest bucket itself is covered by redo_chunk/2. COALESCE
  covers cold start (empty target = backfill from the source's oldest row).
  nil = no source rows ahead, nothing to do.
  """
  def watermark_sql(%{table: table, source: source, bucket: bucket}) do
    "SELECT UNIX_TIMESTAMP(MIN(ts)) FROM #{source} WHERE ts >= " <>
      "COALESCE((SELECT MAX(ts) + INTERVAL #{bucket} SECOND FROM #{table}), '1970-01-01')"
  end

  @doc """
  The idempotent per-chunk upsert. Interpolated identifiers/literals are
  module constants, never user input. GROUP BY is positional (1,2,3 = the
  select list) so the bucket expression is grouped without repetition.
  """
  def upsert_sql(%{table: table, source: source, bucket: bucket, select: select}) do
    "INSERT INTO #{table} (instance_id, metric, ts, value_sum, value_min, value_max, sample_count) " <>
      "SELECT instance_id, metric, FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV #{bucket} * #{bucket}), " <>
      "#{select} FROM #{source} WHERE ts >= ? AND ts < ? GROUP BY 1, 2, 3 " <>
      "ON DUPLICATE KEY UPDATE value_sum = VALUES(value_sum), value_min = VALUES(value_min), " <>
      "value_max = VALUES(value_max), sample_count = VALUES(sample_count)"
  end

  @doc """
  Aligned `{from, to}` chunk bounds covering `[start, end_bound)`, capped at
  `max_chunks` per run (the rest is picked up by the next scheduler tick).
  `start` must be bucket-aligned and `chunk` a bucket multiple, so no chunk
  boundary ever splits a bucket.
  """
  def chunk_ranges(start, end_bound, chunk, max_chunks) do
    start
    |> Stream.iterate(&(&1 + chunk))
    |> Stream.take_while(&(&1 < end_bound))
    |> Enum.take(max_chunks)
    |> Enum.map(&{&1, min(&1 + chunk, end_bound)})
  end

  @doc "Floor a unix timestamp to its bucket start."
  def floor_bucket(unix, bucket), do: div(unix, bucket) * bucket

  defp scalar(sql) do
    case Orbit.Repo.query!(sql).rows do
      [[nil]] -> nil
      [[value]] -> to_int(value)
    end
  end

  defp to_int(%Decimal{} = d), do: d |> Decimal.round() |> Decimal.to_integer()
  defp to_int(v) when is_integer(v), do: v
  defp to_int(v) when is_float(v), do: round(v)

  defp naive(unix), do: unix |> DateTime.from_unix!() |> DateTime.to_naive()
end
