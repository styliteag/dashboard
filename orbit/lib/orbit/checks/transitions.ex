defmodule Orbit.Checks.Transitions do
  @moduledoc """
  Per-check state transitions on every metrics push — port of the python
  ingest chain (hub.py: _debounce_ping_checks → diff_checks →
  record_check_events → check_alert → dispatch_async).

  Diffs the RAW evaluate stage (`Evaluate.evaluate/1` on the hub cache
  entry — deliberately BEFORE the overlay: staleness caps and maintenance
  ceilings are surface presentation, not state changes worth alerting).
  Flap-prone single-measurement families (connectivity/tunnel-ping/iface
  error-rate) are held at OK until the failure persisted for 3 consecutive
  pushes; recovery is immediate (named-mistake 19).

  Baselines and streaks are in-memory only, deliberately WITHOUT the
  python status_snapshot hydrate: that column stays python-hub property
  until cutover (cache.ex contract). Consequence: after an orbit restart
  the first push per instance sets a silent baseline (diff against nil =
  no transitions) — a restart can miss one transition but can never fire
  a restart storm; streaks restart at 0, which only delays a flap alert.

  One GenServer serialises the per-instance state; the evaluate itself is
  pure over the cache entry (~ms per push), history rows go to the shared
  check_events table, alerts dispatch fire-and-forget.
  """

  use GenServer

  require Logger

  alias Orbit.Checks.Evaluate
  alias Orbit.Checks.ServiceCheck

  @flap_prefixes ["connectivity:", "ipsec.tunnel_ping:", "iface_errors:"]
  @flap_polls 3

  @state_icon %{0 => "✅", 1 => "⚠️", 2 => "🔴", 3 => "❔"}
  @state_level %{0 => "info", 1 => "warning", 2 => "error", 3 => "warning"}

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Called by the agent socket after each ingested push (fire-and-forget)."
  def push_evaluated(server \\ __MODULE__, instance_id) do
    GenServer.cast(server, {:push, instance_id})
  catch
    :exit, _ -> :ok
  end

  # -- pure ports (unit-tested) ----------------------------------------------

  @doc "history.diff_checks port: prev nil = silent baseline, missing key = OK."
  def diff(nil, _checks), do: []

  def diff(prev, checks) do
    for c <- checks, Map.get(prev, c.key, 0) != c.state do
      %{
        check_key: c.key,
        old_state: Map.get(prev, c.key, 0),
        new_state: c.state,
        summary: c.summary
      }
    end
  end

  @doc "history.current_states port: the next baseline snapshot."
  def current_states(checks), do: Map.new(checks, &{&1.key, &1.state})

  @doc """
  _debounce_ping_checks port: flap-prone non-OK checks are reported OK until
  the failure persisted @flap_polls consecutive pushes; instant recovery
  (the streak resets by absence). Returns {checks, new_streaks}.
  """
  def debounce(checks, prev_streaks) do
    Enum.map_reduce(checks, %{}, fn %ServiceCheck{} = c, streaks ->
      if not String.starts_with?(c.key, @flap_prefixes) or c.state == 0 do
        {c, streaks}
      else
        streak = Map.get(prev_streaks, c.key, 0) + 1
        held = if streak >= @flap_polls, do: c, else: %ServiceCheck{c | state: 0}
        {held, Map.put(streaks, c.key, streak)}
      end
    end)
  end

  @doc "converters.check_alert port: {title, message, level, check_key}."
  def check_alert(instance_name, t) do
    icon = Map.get(@state_icon, t.new_state, "❔")
    level = Map.get(@state_level, t.new_state, "warning")
    {"#{icon} #{instance_name}: #{t.summary}", t.summary, level, t.check_key}
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok) do
    {:ok, %{prev: %{}, streaks: %{}}}
  end

  @impl true
  def handle_cast({:push, instance_id}, state) do
    checks = instance_id |> Orbit.Hub.cache_entry() |> Evaluate.evaluate()
    {checks, streaks} = debounce(checks, Map.get(state.streaks, instance_id, %{}))
    transitions = diff(Map.get(state.prev, instance_id), checks)

    if transitions != [], do: record_and_alert(instance_id, transitions)

    {:noreply,
     %{
       state
       | prev: Map.put(state.prev, instance_id, current_states(checks)),
         streaks: Map.put(state.streaks, instance_id, streaks)
     }}
  rescue
    # A failing evaluate must never kill the transition tracker.
    error ->
      Logger.warning("checks.transitions_failed error=#{Exception.message(error)}")
      {:noreply, state}
  end

  defp record_and_alert(instance_id, transitions) do
    name = instance_name(instance_id)
    now = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

    for t <- transitions do
      Orbit.Repo.query!(
        "INSERT INTO check_events (instance_id, ts, check_key, old_state, new_state, summary) " <>
          "VALUES (?, ?, ?, ?, ?, ?)",
        [
          instance_id,
          now,
          String.slice(t.check_key, 0, 128),
          t.old_state,
          t.new_state,
          String.slice(t.summary, 0, 255)
        ]
      )

      {title, message, level, key} = check_alert(name, t)
      Orbit.Notifier.dispatch_async(title, message, instance_id, level, key)
    end

    :ok
  rescue
    error -> Logger.warning("checks.transition_record_failed error=#{Exception.message(error)}")
  end

  defp instance_name(instance_id) do
    case Orbit.Repo.query!("SELECT name FROM instances WHERE id = ?", [instance_id]).rows do
      [[name]] -> name
      _ -> "instance ##{instance_id}"
    end
  end
end
