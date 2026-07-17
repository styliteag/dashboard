defmodule Orbit.Availability do
  @moduledoc """
  Availability transitions for push instances — port of the python flip
  sites (hub.py push-recovery + poller/scheduler._check_stale_agents).
  Both stacks share the columns AND the guards, so during parallel dev
  operation whichever stack flips first wins and the other stays silent
  (is_online + guarded update make the transition idempotent across them).

  - `stamp_push/2` — per metrics push: stamp agent_last_seen/last_success,
    detect offline→online and fire the recovered alert + history row.
  - `sweep/0` — scheduler job: flip silent agents offline. The silence
    threshold scales with the instance's push interval (~4 missed pushes),
    floored at agent_stale_seconds; the process-start floor keeps a
    backend restart from counting its own downtime as agent silence
    (python incident 2026-07-12: 5-min outage → 140-alert storm). The flip
    is a guarded UPDATE (agent_last_seen unchanged since the snapshot) so
    an agent reconnecting mid-sweep is never clobbered.

  History rows go to the shared check_events table (availability key,
  OK=0/CRIT=2); alerts dispatch AFTER the DB work, fire-and-forget.
  """

  require Logger

  @availability "availability"
  @ok 0
  @crit 2
  @missed_pushes 4

  @started_key {__MODULE__, :started_at}

  # -- pure helpers (unit-tested, python-parity) -----------------------------

  @doc "instances.is_online port: last success present and newer than last error."
  def online?(last_success_at, last_error_at) do
    last_success_at != nil and
      (last_error_at == nil or NaiveDateTime.compare(last_success_at, last_error_at) == :gt)
  end

  @doc "Silence tolerated before offline: max(floor, ~4 missed effective pushes)."
  def stale_threshold(push_interval, default_push, base_stale_seconds) do
    effective =
      if is_integer(push_interval) and push_interval > 0, do: push_interval, else: default_push

    max(base_stale_seconds, @missed_pushes * effective)
  end

  @doc "Silent longer than threshold? ignore_before floors the silence clock."
  def stale?(now, agent_last_seen, threshold_seconds, ignore_before) do
    floor =
      if ignore_before != nil and NaiveDateTime.compare(ignore_before, agent_last_seen) == :gt,
        do: ignore_before,
        else: agent_last_seen

    NaiveDateTime.diff(now, floor, :second) > threshold_seconds
  end

  # -- push-path: stamp + recovery (agent_socket) ----------------------------

  @doc """
  Stamp a push and fire the recovered alert on the offline→online edge.
  Failures log and never raise — the socket must survive any DB hiccup.
  """
  def stamp_push(instance_id, now) do
    naive = now |> DateTime.truncate(:second) |> DateTime.to_naive()

    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT name, last_success_at, last_error_at FROM instances WHERE id = ?",
        [instance_id]
      )

    was_offline =
      case rows do
        [[_name, success, error]] -> not online?(success, error) and (success || error) != nil
        _ -> false
      end

    Orbit.Repo.query!(
      "UPDATE instances SET agent_last_seen = ?, last_success_at = ?, " <>
        "last_error_at = NULL, last_error_message = NULL WHERE id = ?",
      [naive, naive, instance_id]
    )

    if was_offline do
      [[name, _, _]] = rows
      record_event(instance_id, naive, true, "#{name} recovered")

      Orbit.Notifier.dispatch_async(
        "✅ #{name} is back online",
        "Instance #{name} recovered.",
        instance_id,
        "info",
        @availability
      )
    end

    :ok
  rescue
    error ->
      Logger.warning("agent.stamp_failed error=#{Exception.message(error)}")
      :ok
  end

  # -- scheduler sweep: silent agents flip offline ---------------------------

  @doc "Scheduler entry point (60s): flip silent push agents offline + alert."
  def sweep do
    base = Orbit.Settings.effective("agent_stale_seconds")
    default_push = Orbit.Settings.effective("push_interval_seconds")

    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT id, name, push_interval_seconds, agent_last_seen, " <>
          "last_success_at, last_error_at FROM instances " <>
          "WHERE deleted_at IS NULL AND transport = 'push' AND agent_last_seen IS NOT NULL"
      )

    flagged =
      for [id, name, push_interval, last_seen, success, error] <- rows,
          threshold = stale_threshold(push_interval, default_push, base),
          stale?(NaiveDateTime.utc_now(), last_seen, threshold, started_at()),
          online?(success, error),
          flip_offline(id, last_seen, threshold),
          do: {name, id, threshold}

    for {name, id, threshold} <- flagged do
      Logger.warning("agent.stale instance=#{name} instance_id=#{id}")

      Orbit.Notifier.dispatch_async(
        "🔴 #{name} agent offline",
        "No metrics push from #{name} for over #{threshold}s.",
        id,
        "error",
        @availability
      )
    end

    :ok
  rescue
    error -> Logger.warning("availability.sweep_failed error=#{Exception.message(error)}")
  end

  # Guarded flip: only wins when no fresher push landed since our snapshot
  # (agent_last_seen unchanged — only the push path writes it).
  defp flip_offline(id, snapshot_last_seen, threshold) do
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    %{num_rows: n} =
      Orbit.Repo.query!(
        "UPDATE instances SET last_error_at = ?, last_error_message = ? " <>
          "WHERE id = ? AND agent_last_seen = ?",
        [now, "agent silent for >#{threshold}s", id, snapshot_last_seen]
      )

    if n > 0, do: record_event(id, now, false, "agent silent for >#{threshold}s")
    n > 0
  end

  defp record_event(instance_id, naive_ts, online, summary) do
    {old_state, new_state} = if online, do: {@crit, @ok}, else: {@ok, @crit}

    Orbit.Repo.query!(
      "INSERT INTO check_events (instance_id, ts, check_key, old_state, new_state, summary) " <>
        "VALUES (?, ?, ?, ?, ?, ?)",
      [instance_id, naive_ts, @availability, old_state, new_state, String.slice(summary, 0, 255)]
    )

    :ok
  rescue
    # History is best-effort — a failed insert must not block the flip/alert.
    error -> Logger.warning("availability.event_failed error=#{Exception.message(error)}")
  end

  # Process-start floor, established lazily on the first sweep after boot.
  defp started_at do
    case :persistent_term.get(@started_key, nil) do
      nil ->
        now = NaiveDateTime.utc_now()
        :persistent_term.put(@started_key, now)
        now

      ts ->
        ts
    end
  end
end
