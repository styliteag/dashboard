defmodule Orbit.Access.Store do
  @moduledoc """
  Access accounting — who uses the dashboard, persistent and flood-proof.
  Port of access/store.py (ADR docs/access-log.md), writing the SAME
  alembic-owned tables as the python stack (upserts additive, prune
  idempotent — both stacks can account concurrently).

  - `access_stats` — per (hour, principal) counter upsert; counts EVERY
    request, cardinality is hours × active principals (DR-AL2).
  - `access_events` — sampled per-request rows, hard-capped per flush
    interval. Only user sessions are sampled: anon requests aggregate
    without IP rows (DR-AL8); orbit has no api-key surface yet.
  - `auth_sessions` — login-session bookkeeping (DR-AL3, NOT enforcement):
    row on login, throttled last_seen stamps via the flush cycle, the
    expiry sweep turns the silent 12h cookie death into a real
    `auth.session_expired` audit event (DR-AL4).

  The request path only casts into bounded in-process buffers; a 15s timer
  flushes (swap-then-write: a failed flush loses at most one interval), a
  5-min timer expires, a daily timer prunes with batched oldest-first
  deletes (gap-lock rule), retention days from the settings registry.
  """

  use GenServer

  require Logger

  @flush_ms 15_000
  @expire_ms 5 * 60_000
  @prune_ms 24 * 60 * 60_000

  @events_per_flush 50
  @last_seen_throttle_ms 60_000
  @prune_batch 10_000

  # Keep in sync with the python SessionMiddleware max_age (12h) — the
  # registry sweep must agree with when the cookie actually dies.
  @session_max_age_s 12 * 60 * 60

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Fresh 32-hex session id (uuid4-hex parity)."
  def new_sid, do: Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

  @doc "Count one request (bounded buffers; safe without the server: drop)."
  def record_request(ptype, pkey, ip, method, path, status, opts \\ []) do
    # No double-default head: a 7-arg call once bound server="user" and
    # 500'd every page via before_send (hub.ex:92 lesson, relearned live).
    record_request_on(__MODULE__, ptype, pkey, ip, method, path, status, opts)
  end

  @doc false
  def record_request_on(server, ptype, pkey, ip, method, path, status, opts) do
    GenServer.cast(server, {:record, ptype, pkey, ip, method, path, status, Map.new(opts)})
  catch
    :exit, _ -> :ok
  end

  @doc "Registry row for a freshly minted login session (synchronous)."
  def open_session(server \\ __MODULE__, sid, user_id, ip) do
    GenServer.call(server, {:open_session, sid, user_id, ip})
  catch
    :exit, _ -> :ok
  end

  @doc "Mark a registry row ended (logout). Unknown/missing sid: no-op."
  def close_session(server \\ __MODULE__, sid, reason)
  def close_session(_server, nil, _reason), do: :ok

  def close_session(server, sid, reason) do
    GenServer.call(server, {:close_session, sid, reason})
  catch
    :exit, _ -> :ok
  end

  @doc "Synchronous flush (test/ops seam); returns the aggregated count."
  def flush(server \\ __MODULE__), do: GenServer.call(server, :flush)

  # -- pure buffer transitions (unit-tested) --------------------------------

  @doc false
  def empty_buffers do
    %{agg: %{}, last_ip: %{}, events: [], seen: %{}, stamped: %{}}
  end

  @doc false
  def add_request(buffers, ptype, pkey, ip, method, path, status, opts, now, mono_ms) do
    buffers
    |> bump_agg(ptype, pkey, ip)
    |> sample_event(ptype, ip, method, path, status, opts[:user_id], now)
    |> stamp_seen(opts[:sid], now, mono_ms)
  end

  defp bump_agg(buffers, ptype, pkey, ip) do
    agg = Map.update(buffers.agg, {ptype, pkey}, 1, &(&1 + 1))

    last_ip =
      if ip in [nil, ""] do
        buffers.last_ip
      else
        Map.put(buffers.last_ip, {ptype, pkey}, String.slice(ip, 0, 45))
      end

    %{buffers | agg: agg, last_ip: last_ip}
  end

  # Only user sessions are sampled — anon aggregates without IP rows
  # (DR-AL8: data minimisation; forensics detail stays in the docker log).
  defp sample_event(buffers, "user", ip, method, path, status, user_id, now) do
    event = %{
      ts: now,
      user_id: user_id,
      ip: String.slice(ip || "?", 0, 45),
      method: String.slice(method, 0, 8),
      path: String.slice(path, 0, 255),
      status: status
    }

    %{buffers | events: Enum.take([event | buffers.events], @events_per_flush)}
  end

  defp sample_event(buffers, _ptype, _ip, _method, _path, _status, _user_id, _now), do: buffers

  defp stamp_seen(buffers, nil, _now, _mono_ms), do: buffers

  defp stamp_seen(buffers, sid, now, mono_ms) do
    case buffers.stamped[sid] do
      last when is_integer(last) and mono_ms - last < @last_seen_throttle_ms ->
        buffers

      _ ->
        %{
          buffers
          | stamped: Map.put(buffers.stamped, sid, mono_ms),
            seen: Map.put(buffers.seen, sid, now)
        }
    end
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok) do
    Process.send_after(self(), :flush, @flush_ms)
    Process.send_after(self(), :expire, @expire_ms)
    Process.send_after(self(), :prune, @prune_ms)
    {:ok, empty_buffers()}
  end

  @impl true
  def handle_cast({:record, ptype, pkey, ip, method, path, status, opts}, buffers) do
    now = DateTime.utc_now()
    mono = System.monotonic_time(:millisecond)
    {:noreply, add_request(buffers, ptype, pkey, ip, method, path, status, opts, now, mono)}
  end

  @impl true
  def handle_call({:open_session, sid, user_id, ip}, _from, buffers) do
    now = DateTime.utc_now() |> DateTime.to_naive()

    Orbit.Repo.query!(
      "INSERT INTO auth_sessions (sid, user_id, ip, created_at, last_seen_at) " <>
        "VALUES (?, ?, ?, ?, ?)",
      [sid, user_id, ip && String.slice(ip, 0, 45), now, now]
    )

    stamped = Map.put(buffers.stamped, sid, System.monotonic_time(:millisecond))
    {:reply, :ok, %{buffers | stamped: stamped}}
  rescue
    error ->
      Logger.warning("access.open_session_failed error=#{Exception.message(error)}")
      {:reply, :error, buffers}
  end

  def handle_call({:close_session, sid, reason}, _from, buffers) do
    Orbit.Repo.query!(
      "UPDATE auth_sessions SET ended_at = ?, end_reason = ? " <>
        "WHERE sid = ? AND ended_at IS NULL",
      [DateTime.utc_now() |> DateTime.to_naive(), reason, sid]
    )

    buffers = %{
      buffers
      | stamped: Map.delete(buffers.stamped, sid),
        seen: Map.delete(buffers.seen, sid)
    }

    {:reply, :ok, buffers}
  rescue
    error ->
      Logger.warning("access.close_session_failed error=#{Exception.message(error)}")
      {:reply, :error, buffers}
  end

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

  def handle_info(:expire, buffers) do
    Process.send_after(self(), :expire, @expire_ms)
    expire_sessions()
    {:noreply, buffers}
  end

  def handle_info(:prune, buffers) do
    Process.send_after(self(), :prune, @prune_ms)
    prune()
    {:noreply, buffers}
  end

  # Swap-then-write (throttle stamps survive — they are bookkeeping, not data).
  defp do_flush(%{agg: agg, events: events, seen: seen} = buffers)
       when agg == %{} and events == [] and seen == %{} do
    {0, buffers}
  end

  defp do_flush(buffers) do
    %{agg: agg, last_ip: last_ip, events: events, seen: seen} = buffers
    rest = %{buffers | agg: %{}, last_ip: %{}, events: [], seen: %{}}

    now = DateTime.utc_now() |> DateTime.to_naive()
    bucket = %{now | minute: 0, second: 0, microsecond: {0, 0}}

    for {{ptype, pkey}, n} <- agg do
      Orbit.Repo.query!(
        "INSERT INTO access_stats (bucket, principal_type, principal_key, count, last_ip) " <>
          "VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE count = count + ?, " <>
          "last_ip = COALESCE(?, last_ip)",
        [bucket, ptype, pkey, n, last_ip[{ptype, pkey}], n, last_ip[{ptype, pkey}]]
      )
    end

    for e <- Enum.reverse(events) do
      Orbit.Repo.query!(
        "INSERT INTO access_events (ts, user_id, ip, method, path, status) " <>
          "VALUES (?, ?, ?, ?, ?, ?)",
        [DateTime.to_naive(e.ts), e.user_id, e.ip, e.method, e.path, e.status]
      )
    end

    for {sid, ts} <- seen do
      Orbit.Repo.query!(
        "UPDATE auth_sessions SET last_seen_at = ? WHERE sid = ? AND ended_at IS NULL",
        [DateTime.to_naive(ts), sid]
      )
    end

    n = agg |> Map.values() |> Enum.sum()
    if n > 0, do: Logger.debug("access.flushed requests=#{n}")
    {n, rest}
  rescue
    error ->
      Logger.warning("access.flush_failed error=#{Exception.message(error)}")
      {0, %{buffers | agg: %{}, last_ip: %{}, events: [], seen: %{}}}
  end

  # Bookkeeping, not enforcement (DR-AL3/AL4): the cookie died on its own at
  # max_age — here the silent auto-logout becomes a visible audit event.
  defp expire_sessions do
    cutoff =
      DateTime.utc_now() |> DateTime.add(-@session_max_age_s, :second) |> DateTime.to_naive()

    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT sid, user_id, ip FROM auth_sessions " <>
          "WHERE ended_at IS NULL AND created_at < ?",
        [cutoff]
      )

    now = DateTime.utc_now() |> DateTime.to_naive()

    for [sid, user_id, ip] <- rows do
      Orbit.Repo.query!(
        "UPDATE auth_sessions SET ended_at = ?, end_reason = 'expired' WHERE sid = ?",
        [now, sid]
      )

      Orbit.Audit.write(
        action: "auth.session_expired",
        result: "ok",
        user_id: user_id,
        source_ip: ip
      )
    end

    if rows != [], do: Logger.info("access.sessions_expired sessions=#{length(rows)}")
    :ok
  rescue
    error -> Logger.warning("access.expire_failed error=#{Exception.message(error)}")
  end

  defp prune do
    events_days = Orbit.Settings.effective("access_events_retention_days")
    stats_days = Orbit.Settings.effective("access_stats_retention_days")
    sessions_days = Orbit.Settings.effective("access_sessions_retention_days")

    now = DateTime.utc_now()
    prune_events_batched(now |> DateTime.add(-events_days, :day) |> DateTime.to_naive())

    Orbit.Repo.query!(
      "DELETE FROM access_stats WHERE bucket < ?",
      [now |> DateTime.add(-stats_days, :day) |> DateTime.to_naive()]
    )

    Orbit.Repo.query!(
      "DELETE FROM auth_sessions WHERE ended_at IS NOT NULL AND ended_at < ?",
      [now |> DateTime.add(-sessions_days, :day) |> DateTime.to_naive()]
    )

    :ok
  rescue
    error -> Logger.warning("access.prune_failed error=#{Exception.message(error)}")
  end

  defp prune_events_batched(cutoff) do
    %{num_rows: n} =
      Orbit.Repo.query!(
        "DELETE FROM access_events WHERE ts < ? ORDER BY ts LIMIT ?",
        [cutoff, @prune_batch]
      )

    if n >= @prune_batch, do: prune_events_batched(cutoff)
  end
end
