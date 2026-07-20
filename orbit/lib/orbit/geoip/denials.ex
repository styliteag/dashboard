defmodule Orbit.GeoIP.Denials do
  @moduledoc """
  Denial accounting for the GeoIP/CrowdSec gate (DR-G9) — port of
  geoip/denials.py, writing the SAME alembic-owned tables as the python
  stack (upserts are additive, prune is idempotent — both stacks can run).

  Two tiers:
  - `geoip_denial_stats` — per (day, reason, country) aggregate, upserted
    on flush. Bounded by days × ~4 reasons × ~250 countries; counts EVERY
    denial and is the source of truth for totals.
  - `geoip_denial_events` — individual rows for the recent-denials view,
    hard-capped per flush interval (#{50}): under a flood only a sample
    lands here while the aggregate still counts everything.

  The request path only casts into bounded in-process buffers (a scanner
  cycling random IPs can neither flood a table nor grow memory); a 15s
  timer flushes, a daily timer prunes (batched oldest-first deletes — an
  unbounded DELETE gap-locks, repo incident rule). Buffers are swapped out
  before the write, so a failed flush loses at most one interval —
  acceptable for statistics.

  The python-side Prometheus mirrors / snapshot view stay python-owned
  until orbit grows its Access surface; this module's job is that no orbit
  denial is lost to those surfaces.
  """

  use GenServer

  require Logger

  @flush_ms 15_000
  @prune_ms 24 * 60 * 60_000
  @events_per_flush 50
  @event_retention_days 30
  @stats_retention_days 365
  @prune_batch 10_000

  @fail_open_reason "fail_open"

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Count one denial (bounded buffers; safe without the server: drop)."
  def record(server \\ __MODULE__, ip, country, path, reason) do
    GenServer.cast(server, {:record, ip, country, path, reason})
  catch
    :exit, _ -> :ok
  end

  @doc "Count one DR-G5 fail-open allow (stats row only, not a denial)."
  def record_fail_open(server \\ __MODULE__) do
    GenServer.cast(server, :record_fail_open)
  catch
    :exit, _ -> :ok
  end

  @doc "Synchronous flush (test/ops seam); returns the aggregated count."
  def flush(server \\ __MODULE__), do: GenServer.call(server, :flush)

  # -- pure buffer transitions (unit-tested) --------------------------------

  @doc false
  def empty_buffers, do: %{agg: %{}, events: []}

  @doc false
  def add_denial(buffers, ip, country, path, reason, now) do
    event = %{
      ts: now,
      ip: String.slice(ip || "?", 0, 45),
      country: country,
      path: String.slice(path, 0, 255),
      reason: String.slice(reason, 0, 32)
    }

    %{
      agg: Map.update(buffers.agg, {reason, country || "??"}, 1, &(&1 + 1)),
      # Newest-first, hard cap: python's deque(maxlen) keeps the newest
      # sample under a flood; prepend + take does the same here.
      events: Enum.take([event | buffers.events], @events_per_flush)
    }
  end

  @doc false
  def add_fail_open(buffers) do
    %{buffers | agg: Map.update(buffers.agg, {@fail_open_reason, "??"}, 1, &(&1 + 1))}
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok) do
    Process.send_after(self(), :flush, @flush_ms)
    Process.send_after(self(), :prune, @prune_ms)
    # Lock-free counter for the all-pages footer. An ETS read costs
    # microseconds and needs no message to this process — a GenServer.call
    # on every rendered page would serialise the whole site through here,
    # and a COUNT(*) per page would hit the database just as often.
    :ets.new(@counter_table, [:named_table, :public, :set, write_concurrency: true])
    :ets.insert(@counter_table, {:blocked, 0})
    {:ok, empty_buffers()}
  end

  @counter_table :orbit_geoip_denial_count

  @doc """
  Denials since this process started (footer badge).

  Deliberately process-local and not a query: it answers "is the gate doing
  anything right now", the same live-health semantics as the hub counters.
  Returns 0 before the table exists (boot, or tests without the supervisor).
  """
  def blocked_count do
    case :ets.lookup(@counter_table, :blocked) do
      [{:blocked, n}] -> n
      _ -> 0
    end
  rescue
    ArgumentError -> 0
  end

  @impl true
  def handle_cast({:record, ip, country, path, reason}, buffers) do
    bump_counter()
    {:noreply, add_denial(buffers, ip, country, path, reason, DateTime.utc_now())}
  end

  defp bump_counter do
    :ets.update_counter(@counter_table, :blocked, 1)
  rescue
    ArgumentError -> 0
  end

  def handle_cast(:record_fail_open, buffers) do
    {:noreply, add_fail_open(buffers)}
  end

  @impl true
  def handle_call(:flush, _from, buffers) do
    {n, rest} = do_flush(buffers)
    {:reply, n, rest}
  end

  @impl true
  def handle_info(:flush, buffers) do
    Process.send_after(self(), :flush, @flush_ms)
    {_n, rest} = do_flush(buffers)
    {:noreply, rest}
  end

  def handle_info(:prune, buffers) do
    Process.send_after(self(), :prune, @prune_ms)
    prune()
    {:noreply, buffers}
  end

  # Swap-then-write: a failed flush loses at most one interval (moduledoc).
  defp do_flush(%{agg: agg, events: events}) when agg == %{} and events == [] do
    {0, empty_buffers()}
  end

  defp do_flush(%{agg: agg, events: events}) do
    bucket = Date.utc_today()

    for {{reason, country}, n} <- agg do
      # MariaDB-native upsert (repo rule: no ON CONFLICT idioms).
      Orbit.Repo.query!(
        "INSERT INTO geoip_denial_stats (bucket, reason, country, count) " <>
          "VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE count = count + ?",
        [bucket, reason, country, n, n]
      )
    end

    for e <- Enum.reverse(events) do
      Orbit.Repo.query!(
        "INSERT INTO geoip_denial_events (ts, ip, country, path, reason) VALUES (?, ?, ?, ?, ?)",
        [DateTime.to_naive(e.ts), e.ip, e.country, e.path, e.reason]
      )
    end

    n = agg |> Map.values() |> Enum.sum()
    if n > 0, do: Logger.debug("geoip.denials_flushed denials=#{n}")
    {n, empty_buffers()}
  rescue
    error ->
      Logger.warning("geoip.denials_flush_failed error=#{Exception.message(error)}")
      {0, empty_buffers()}
  end

  defp prune do
    event_cutoff =
      DateTime.utc_now() |> DateTime.add(-@event_retention_days, :day) |> DateTime.to_naive()

    prune_events_batched(event_cutoff)

    stats_cutoff = Date.add(Date.utc_today(), -@stats_retention_days)
    Orbit.Repo.query!("DELETE FROM geoip_denial_stats WHERE bucket < ?", [stats_cutoff])
    :ok
  rescue
    error -> Logger.warning("geoip.denials_prune_failed error=#{Exception.message(error)}")
  end

  defp prune_events_batched(cutoff) do
    %{num_rows: n} =
      Orbit.Repo.query!(
        "DELETE FROM geoip_denial_events WHERE ts < ? ORDER BY ts LIMIT ?",
        [cutoff, @prune_batch]
      )

    if n >= @prune_batch, do: prune_events_batched(cutoff)
  end
end
