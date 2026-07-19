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

  @doc "Delete raw metrics older than metrics_retention_days. Returns rows deleted."
  @spec prune_metrics() :: non_neg_integer()
  def prune_metrics do
    days = Orbit.Settings.effective("metrics_retention_days")
    deleted = prune_before("metrics", cutoff(days))
    if deleted > 0, do: Logger.info("metrics.pruned raw=#{deleted}")
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
