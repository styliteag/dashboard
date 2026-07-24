defmodule Orbit.Maintenance.Prune do
  @moduledoc """
  Batched time-retention pruning — port of maintenance/jobs.py.

  `prune_before/2` deletes oldest-first in bounded batches
  (`DELETE ... WHERE ts < cutoff ORDER BY ts LIMIT n`, commit, pause, repeat).
  The ORDER BY ts is load-bearing: it drives each batch off the ts index and
  confines the row/gap locks to the OLDEST rows, never the recent range where
  fresh inserts land. An unbounded DELETE gap-locked the metrics table and
  500'd the API for ~80s every hour (the named incident) — never remove the
  batching or the ORDER BY.

  These jobs are idempotent (they only delete already-old rows), so running
  them alongside the python backend's own prune during the transition is
  harmless — unlike poll/notify jobs, a double prune just no-ops the second
  time.
  """

  require Logger

  @batch_size 10_000
  @batch_pause_ms 100

  @doc """
  Batched `DELETE FROM <table> WHERE ts < cutoff`. `table` MUST be an internal
  constant (interpolated into SQL — never pass user input). Returns rows
  deleted.
  """
  @spec prune_before(String.t(), DateTime.t()) :: non_neg_integer()
  def prune_before(table, cutoff) do
    naive = cutoff |> DateTime.truncate(:second) |> DateTime.to_naive()
    sql = "DELETE FROM #{table} WHERE ts < ? ORDER BY ts LIMIT #{@batch_size}"
    loop(sql, naive, 0)
  end

  defp loop(sql, cutoff, acc) do
    %{num_rows: n} = Orbit.Repo.query!(sql, [cutoff])
    acc = acc + n

    if n < @batch_size do
      acc
    else
      Process.sleep(@batch_pause_ms)
      loop(sql, cutoff, acc)
    end
  end

  @doc """
  Delete raw metrics older than metrics_retention_days — but never rows the
  5m rollup has not aggregated yet. Returns rows deleted.

  The 2026-07-24 incident this guards against: retention was lowered from
  30 to 7 days on the same day the rollup tiers shipped, and the prune ate
  three weeks of raw history while the post-upgrade backfill was still
  working toward it — the long-range chart tiers have permanent holes for
  that window. The rollup watermark (`MAX(ts)` of the tier) is the safe
  floor: every source row STRICTLY OLDER than it lies in a completed,
  already-aggregated bucket.
  """
  @spec prune_metrics() :: non_neg_integer()
  def prune_metrics do
    days = Orbit.Settings.effective("metrics_retention_days")

    case rollup_capped_cutoff("metrics", cutoff(days), watermark("metrics_5m")) do
      nil ->
        0

      cut ->
        deleted = prune_before("metrics", cut)
        if deleted > 0, do: Logger.info("metrics.pruned raw=#{deleted}")
        deleted
    end
  end

  @doc "Delete 5-minute rollups older than metrics_5m_retention_days (same rollup guard, against the 1h tier). Returns rows deleted."
  @spec prune_metrics_5m() :: non_neg_integer()
  def prune_metrics_5m do
    days = Orbit.Settings.effective("metrics_5m_retention_days")

    case rollup_capped_cutoff("metrics_5m", cutoff(days), watermark("metrics_1h")) do
      nil ->
        0

      cut ->
        deleted = prune_before("metrics_5m", cut)
        if deleted > 0, do: Logger.info("metrics_5m.pruned rows=#{deleted}")
        deleted
    end
  end

  @doc """
  The effective prune cutoff for a table whose rows feed a rollup tier:
  the retention cutoff, floored at the tier's watermark. Pure — the DB
  reads live in the callers.

  - Watermark `nil` (empty tier) = nothing aggregated yet. On a fresh
    install there is nothing old enough to prune anyway; mid-upgrade it is
    exactly the backfill about to start. Skip the prune (`nil`) — the tier
    fills within minutes and the next hourly run proceeds.
  - Watermark older than the retention cutoff = the rollup is behind
    (stalled jobs, or retention was just lowered past the backfill). Prune
    only up to the watermark and say so loudly — this is the state that
    silently cost history once, and it also means raw is outliving its
    retention, which must not stay invisible either.
  """
  @spec rollup_capped_cutoff(String.t(), DateTime.t(), DateTime.t() | nil) ::
          DateTime.t() | nil
  def rollup_capped_cutoff(table, retention_cutoff, watermark) do
    cond do
      is_nil(watermark) ->
        Logger.info("#{table}.prune_skipped_empty_rollup")
        nil

      DateTime.compare(watermark, retention_cutoff) == :lt ->
        Logger.warning(
          "#{table}.prune_capped_by_rollup watermark=#{DateTime.to_iso8601(watermark)} " <>
            "retention_cutoff=#{DateTime.to_iso8601(retention_cutoff)}"
        )

        watermark

      true ->
        retention_cutoff
    end
  end

  # MAX(ts) of a rollup tier as UTC DateTime, nil when empty or unreachable.
  # Unreachable reads as "don't prune" — the conservative direction.
  defp watermark(table) do
    case Orbit.Repo.query!("SELECT MAX(ts) FROM #{table}").rows do
      [[%NaiveDateTime{} = naive]] -> DateTime.from_naive!(naive, "Etc/UTC")
      _ -> nil
    end
  rescue
    _ -> nil
  catch
    _kind, _reason -> nil
  end

  @doc "Delete hourly rollups older than metrics_1h_retention_days. Returns rows deleted."
  @spec prune_metrics_1h() :: non_neg_integer()
  def prune_metrics_1h do
    days = Orbit.Settings.effective("metrics_1h_retention_days")
    deleted = prune_before("metrics_1h", cutoff(days))
    if deleted > 0, do: Logger.info("metrics_1h.pruned rows=#{deleted}")
    deleted
  end

  @doc "Delete IPsec tunnel events older than the retention window. Returns rows deleted."
  @spec prune_ipsec_events() :: non_neg_integer()
  def prune_ipsec_events do
    days = Orbit.Settings.effective("ipsec_event_retention_days")
    deleted = prune_before("ipsec_tunnel_events", cutoff(days))
    if deleted > 0, do: Logger.info("ipsec_events.pruned rows=#{deleted}")
    deleted
  end

  @doc "Delete check state-change events older than the retention window. Returns rows deleted."
  @spec prune_check_events() :: non_neg_integer()
  def prune_check_events do
    days = Orbit.Settings.effective("check_event_retention_days")
    deleted = prune_before("check_events", cutoff(days))
    if deleted > 0, do: Logger.info("check_events.pruned rows=#{deleted}")
    deleted
  end

  defp cutoff(days), do: DateTime.add(DateTime.utc_now(), -days * 86_400, :second)
end
