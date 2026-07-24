defmodule Orbit.Metrics.RollupTest do
  @moduledoc """
  Rollup cascade (metrics → metrics_5m → metrics_1h): the upsert SQL shape,
  chunk alignment, and the range/tier divisibility invariant that keeps
  chart buckets from straddling rollup rows. SQL is asserted as text (house
  style); the thin Repo.query! runner stays untested.
  """
  use ExUnit.Case, async: true

  alias Orbit.Metrics
  alias Orbit.Metrics.Rollup

  describe "upsert_sql/1" do
    test "5m tier aggregates the raw table into 300s buckets, idempotently" do
      sql = Rollup.upsert_sql(Rollup.tiers()["metrics_5m"])

      assert sql =~ "INSERT INTO metrics_5m"
      assert sql =~ "FROM metrics WHERE ts >= ? AND ts < ?"
      assert sql =~ "FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV 300 * 300)"
      assert sql =~ "SUM(value), MIN(value), MAX(value), COUNT(*)"
      assert sql =~ "GROUP BY 1, 2, 3"
      # Re-running a chunk must overwrite, not duplicate — the watermark
      # re-aggregates the newest bucket on every run.
      assert sql =~ "ON DUPLICATE KEY UPDATE"
    end

    test "1h tier cascades from the 5m tier with count-weighted sums, never avg" do
      sql = Rollup.upsert_sql(Rollup.tiers()["metrics_1h"])

      assert sql =~ "INSERT INTO metrics_1h"
      assert sql =~ "FROM metrics_5m WHERE ts >= ? AND ts < ?"
      assert sql =~ "FROM_UNIXTIME(UNIX_TIMESTAMP(ts) DIV 3600 * 3600)"
      assert sql =~ "SUM(value_sum), MIN(value_min), MAX(value_max), SUM(sample_count)"
      # avg-of-avgs would overweight sparse buckets (agent briefly online);
      # the cascade must carry sum+count and divide only at read time.
      refute sql =~ ~r/avg/i
    end
  end

  describe "watermark_sql/1" do
    test "anchors on the source's next row past the newest bucket's END" do
      # Two prior anchors stalled forever on a source gap (dev-DB incident,
      # stack off for days): target MAX(ts) alone never advanced across
      # empty chunks, and source MIN(ts >= MAX) re-anchored on the newest
      # bucket's own rows when data stopped mid-bucket. The `+ bucket`
      # offset is the fix — it cannot see the newest bucket's own rows.
      sql = Rollup.watermark_sql(Rollup.tiers()["metrics_5m"])
      assert sql =~ "SELECT UNIX_TIMESTAMP(MIN(ts)) FROM metrics"
      assert sql =~ "MAX(ts) + INTERVAL 300 SECOND FROM metrics_5m"
      assert sql =~ "COALESCE"
      assert sql =~ "'1970-01-01'"
    end
  end

  describe "chunk_ranges/4" do
    test "covers the span gaplessly in aligned chunks" do
      assert Rollup.chunk_ranges(0, 10_800, 3_600, 24) ==
               [{0, 3_600}, {3_600, 7_200}, {7_200, 10_800}]
    end

    test "clamps the final chunk to the end bound" do
      assert Rollup.chunk_ranges(0, 4_000, 3_600, 24) == [{0, 3_600}, {3_600, 4_000}]
    end

    test "caps a single run at max_chunks — backfill spreads across ticks" do
      chunks = Rollup.chunk_ranges(0, 1_000_000, 3_600, 24)
      assert length(chunks) == 24
      assert List.last(chunks) == {23 * 3_600, 24 * 3_600}
    end

    test "an already-caught-up watermark yields no chunks" do
      assert Rollup.chunk_ranges(7_200, 7_200, 3_600, 24) == []
    end
  end

  describe "tier alignment invariants" do
    test "chunk sizes are exact bucket multiples — a split bucket would be overwritten short" do
      for {_table, tier} <- Rollup.tiers() do
        assert rem(tier.chunk, tier.bucket) == 0
      end
    end

    test "every UI range bucket divides evenly into its serving tier" do
      # The reason a 10m tier was rejected: 10m does not divide the 7d
      # range's 900s bucket. Any future range or tier must keep this
      # property or bucket boundaries straddle rollup rows and averages
      # smear across buckets.
      for range <- ~w(1h 6h 24h 7d 30d 90d 1y) do
        {_window, bucket} = Metrics.range_bucket(range)

        case Metrics.source_table(bucket) do
          "metrics" -> :ok
          "metrics_5m" -> assert rem(bucket, 300) == 0
          "metrics_1h" -> assert rem(bucket, 3_600) == 0
        end
      end
    end
  end

  describe "floor_bucket/2" do
    test "floors to the bucket start and is idempotent" do
      assert Rollup.floor_bucket(1_753_351_499, 300) == 1_753_351_200
      assert Rollup.floor_bucket(1_753_351_200, 300) == 1_753_351_200
    end
  end
end
