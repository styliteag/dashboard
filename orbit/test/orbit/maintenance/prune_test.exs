defmodule Orbit.Maintenance.PruneTest do
  @moduledoc """
  The rollup guard on the metrics prunes (DB-free — the cutoff decision is
  pure; the batched delete itself is proven live). Regression for
  2026-07-24: a retention drop raced the post-upgrade rollup backfill and
  the prune deleted three weeks of raw rows the tiers had not aggregated
  yet — permanent holes in the long-range charts.
  """

  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Orbit.Maintenance.Prune

  @cutoff ~U[2026-07-17 12:00:00Z]

  test "a healthy rollup leaves the retention cutoff untouched" do
    watermark = ~U[2026-07-24 11:55:00Z]
    assert Prune.rollup_capped_cutoff("metrics", @cutoff, watermark) == @cutoff
  end

  test "a lagging rollup caps the cutoff at its watermark, loudly" do
    # The incident shape: retention says "delete before 07-17" while the
    # backfill has only aggregated up to 07-04 — pruning past the watermark
    # would destroy rows no tier has seen.
    watermark = ~U[2026-07-04 17:00:00Z]

    log =
      capture_log(fn ->
        assert Prune.rollup_capped_cutoff("metrics", @cutoff, watermark) == watermark
      end)

    assert log =~ "metrics.prune_capped_by_rollup"
    assert log =~ "2026-07-04"
  end

  test "an empty rollup tier skips the prune entirely" do
    # Fresh install (nothing old enough to matter) or mid-upgrade right
    # before the backfill's first run — the one moment pruning anything is
    # guaranteed to destroy not-yet-aggregated ground.
    assert Prune.rollup_capped_cutoff("metrics", @cutoff, nil) == nil
  end

  test "a watermark exactly at the cutoff does not cap (rows at the watermark survive the < comparison)" do
    assert Prune.rollup_capped_cutoff("metrics", @cutoff, @cutoff) == @cutoff
  end
end
