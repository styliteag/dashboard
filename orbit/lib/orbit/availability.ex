defmodule Orbit.Availability do
  @moduledoc """
  Availability transitions for push instances — port of the python flip
  sites (hub.py push-recovery + poller/scheduler._check_stale_agents).
  Both stacks share the columns AND the guards, so during parallel dev
  operation whichever stack flips first wins and the other stays silent
  (is_online + guarded update make the transition idempotent across them).

  - `stamp_push/2` / `stamp_poll_ok/3` — per metrics push / successful
    poll: stamp last_success, detect offline→online, fire the recovered
    alert + history row and clear a maintenance flag on that edge
    (`maintenance_on_success/2`).
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

  alias Orbit.Instances.Instance

  @availability "availability"
  @ok 0
  @crit 2
  @missed_pushes 4

  @started_key {__MODULE__, :started_at}

  # Polled boxes: a success older than this no longer counts as reachable.
  @poll_window_seconds 300

  # -- pure helpers (unit-tested, python-parity) -----------------------------

  @typedoc "Availability state of one instance — see `classify/3`."
  @type state :: :online | :degraded | :offline

  @doc """
  The availability state machine, pure: the fleet list's KPI tiles and row
  badges (`Orbit.Instances.status_bucket/3`) and pro host summaries read it.

  - push (agent) boxes: the live WS connection decides — `:online` while
    connected, `:offline` otherwise; timestamps are ignored (a connected
    agent that stopped pushing stays `:online` — staleness is the separate
    `Orbit.Checks.Staleness` verdict).
  - polled boxes (direct/relay), over a #{@poll_window_seconds}s window:
    `:online` = fresh success newer than any error; `:degraded` = fresh
    success AND a fresh error at-or-after it; `:offline` = no fresh success
    (never polled included).

  Not to be confused with `online?/2`, the last-outcome edge detector the
  flip sites use to fire offline/recovered alerts.
  """
  @spec classify(Instance.t(), boolean(), DateTime.t()) :: state()
  def classify(%Instance{} = inst, connected?, now) do
    cond do
      Instance.agent_mode?(inst) and connected? -> :online
      Instance.agent_mode?(inst) -> :offline
      true -> classify_polled(inst.last_success_at, inst.last_error_at, now)
    end
  end

  defp classify_polled(succ, err, now) do
    cutoff = DateTime.add(now, -@poll_window_seconds)

    cond do
      not fresh?(succ, cutoff) -> :offline
      err == nil or DateTime.compare(succ, err) == :gt -> :online
      # err >= succ >= cutoff, so the error is fresh too.
      true -> :degraded
    end
  end

  defp fresh?(nil, _cutoff), do: false
  defp fresh?(ts, cutoff), do: DateTime.compare(ts, cutoff) != :lt

  @doc """
  Timestamp to stamp a push with: the agent's own `ts`, clamped to the
  server clock — an agent clock running ahead must not push
  `agent_last_seen` into the future (that would hide its silence from the
  stale sweep for as long as the skew). No `ts` → server now.
  """
  @spec push_time(DateTime.t() | nil, DateTime.t()) :: DateTime.t()
  def push_time(nil, now), do: now
  def push_time(%DateTime{} = agent_ts, now), do: Enum.min([agent_ts, now], DateTime)

  @doc """
  instances.is_online port: last success present and newer than last
  error. Takes NaiveDateTime (raw SQL rows) or DateTime (schema structs).
  """
  def online?(last_success_at, last_error_at) do
    last_success_at != nil and
      (last_error_at == nil or NaiveDateTime.compare(last_success_at, last_error_at) == :gt)
  end

  @typedoc "Last recorded transport outcome of one instance — see `outcome/2`."
  @type outcome :: :never | :online | :offline

  @doc """
  Last-outcome state from the two stamp columns: `:never` (no attempt yet),
  `:online` (`online?/2`), else `:offline` — which includes a push box the
  stale sweep flipped (it stamps `last_error_at`). The stamp paths read it
  BEFORE writing a success: `:offline` there is the offline→online edge.
  """
  @spec outcome(NaiveDateTime.t() | DateTime.t() | nil, NaiveDateTime.t() | DateTime.t() | nil) ::
          outcome()
  def outcome(nil, nil), do: :never
  def outcome(success, error), do: if(online?(success, error), do: :online, else: :offline)

  @doc """
  Maintenance transition on a successful push or poll, pure. The flag clears
  only on the offline→online edge: the planned-down window is over once a
  box that was offline reports in again. A box that stayed online keeps its
  flag (an operator can hold a healthy box in maintenance as long as they
  like), and so does a box's very first contact (`:never`) — onboarding is
  not a recovery. The flag is set only by hand (instance edit form).
  """
  @spec maintenance_on_success(outcome(), boolean()) :: :clear | :keep
  def maintenance_on_success(:offline, true), do: :clear
  def maintenance_on_success(_prev, _maintenance?), do: :keep

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
        "SELECT name, last_success_at, last_error_at, maintenance FROM instances WHERE id = ?",
        [instance_id]
      )

    {prev, maintenance} =
      case rows do
        [[_name, success, error, maint]] -> {outcome(success, error), maint in [1, true]}
        _ -> {:never, false}
      end

    was_offline = prev == :offline

    Orbit.Repo.query!(
      "UPDATE instances SET agent_last_seen = ?, last_success_at = ?, " <>
        "last_error_at = NULL, last_error_message = NULL WHERE id = ?",
      [naive, naive, instance_id]
    )

    # Maintenance clears on the offline→online edge only, on both transports
    # (stamp_poll_ok/3 too). Clearing on EVERY push (the old python hub.py
    # parity) meant a healthy agent box could not stay in maintenance past
    # one push interval, while polled boxes never cleared at all — and a box
    # in maintenance has all its CRITs capped at WARN, so a forgotten flag
    # silently muted a live firewall. The edge serves both: a planned-down
    # box returning ends its window, a box held in maintenance stays there.
    if maintenance_on_success(prev, maintenance) == :clear do
      [[name, _, _, _]] = rows
      clear_maintenance(instance_id, name, "agent_reported_in")
    end

    if was_offline do
      [[name, _, _, _]] = rows
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
  catch
    # A pool checkout EXITS rather than raising, so the rescue above does not
    # cover a stressed or restarting database — and this runs on the agent
    # socket's own metrics-push path. An exit would kill every agent
    # connection at once and hand the stale sweep a fleet of false offlines,
    # which is the exact opposite of "the socket must survive any DB hiccup".
    kind, reason ->
      Logger.warning("agent.stamp_failed error=#{kind} #{inspect(reason)}")
      :ok
  end

  # -- poll-path: stamp + both edges (poller/scheduler._poll_instance) -------

  @doc """
  Stamp a successful direct poll and fire the recovered alert on the
  offline→online edge. Mirror of `stamp_push/2` for the poll transport — the
  third flip site of the python original, which the first orbit port left out
  (nothing wrote `last_success_at` for direct instances at all, so their
  online/offline state was meaningless).
  """
  def stamp_poll_ok(instance_id, name, %DateTime{} = now) do
    naive = now |> DateTime.truncate(:second) |> DateTime.to_naive()

    {prev, maintenance} =
      case outcome_row(instance_id) do
        [success, error, maint] -> {outcome(success, error), maint in [1, true]}
        _ -> {:never, false}
      end

    was_offline = prev == :offline

    Orbit.Repo.query!(
      "UPDATE instances SET last_success_at = ?, last_error_at = NULL, " <>
        "last_error_message = NULL WHERE id = ?",
      [naive, instance_id]
    )

    if maintenance_on_success(prev, maintenance) == :clear do
      clear_maintenance(instance_id, name, "poll_succeeded")
    end

    if was_offline do
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
      Logger.warning("poll.stamp_failed error=#{Exception.message(error)}")
      :ok
  end

  @doc """
  Stamp a failed direct poll and fire the offline alert on the online→offline
  edge. The message is truncated exactly like python (500 chars in the column,
  200 in the alert and the history row).
  """
  def stamp_poll_error(instance_id, name, %DateTime{} = now, reason) do
    naive = now |> DateTime.truncate(:second) |> DateTime.to_naive()
    message = reason |> to_string() |> String.slice(0, 500)
    was_online = online_before?(instance_id)

    Orbit.Repo.query!(
      "UPDATE instances SET last_error_at = ?, last_error_message = ? WHERE id = ?",
      [naive, message, instance_id]
    )

    if was_online do
      short = String.slice(message, 0, 200)
      record_event(instance_id, naive, false, short)

      Orbit.Notifier.dispatch_async(
        "🔴 #{name} is offline",
        "Instance #{name} failed: #{short}",
        instance_id,
        "error",
        @availability
      )
    end

    :ok
  rescue
    error ->
      Logger.warning("poll.error_stamp_failed error=#{Exception.message(error)}")
      :ok
  end

  defp online_before?(instance_id) do
    case outcome_row(instance_id) do
      [success, error, _maint] -> online?(success, error)
      _ -> false
    end
  end

  defp outcome_row(instance_id) do
    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT last_success_at, last_error_at, maintenance FROM instances WHERE id = ?",
        [instance_id]
      )

    case rows do
      [row] -> row
      _ -> nil
    end
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

  # The offline→online edge of a box in maintenance (`maintenance_on_success/2`
  # said :clear). Guarded on the flag still being set, so a concurrent manual
  # clear does not produce a second audit row and notification.
  defp clear_maintenance(instance_id, name, reason) do
    %{num_rows: n} =
      Orbit.Repo.query!(
        "UPDATE instances SET maintenance = 0 WHERE id = ? AND maintenance <> 0",
        [instance_id]
      )

    if n > 0 do
      Orbit.Audit.write(
        action: "instance.maintenance_cleared",
        result: "ok",
        target_type: "instance",
        target_id: instance_id,
        detail: %{"reason" => reason}
      )

      Orbit.Notifier.dispatch_async(
        "#{name} maintenance ended",
        "#{name} is back online — maintenance flag cleared.",
        instance_id,
        "info",
        @availability
      )
    end

    :ok
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
