defmodule Orbit.Checks.Staleness do
  @moduledoc """
  Agent-staleness resolution for a push instance — port of checks/staleness.py
  + poller/gate.py. A push agent gone silent still serves its last-known
  sub-states from the hub cache; those are stale (unknown, not necessarily
  down). The threshold scales with the instance's effective push interval,
  floored at `agent_stale_seconds`, matching the watchdog so API/export agree.
  """

  alias Orbit.Instances.Instance

  @default_missed_pushes 4

  defstruct [:stale, :age_seconds, :threshold]
  @type t :: %__MODULE__{stale: boolean(), age_seconds: integer(), threshold: integer()}

  @doc """
  Staleness for a push instance, or nil when the concept doesn't apply
  (direct/relay poll, or a push agent that has never reported).

  `push_default` / `stale_floor` are the effective settings values.
  """
  @spec resolve(Instance.t(), integer(), integer(), DateTime.t()) :: t() | nil
  def resolve(%Instance{} = inst, push_default, stale_floor, now) do
    if Instance.agent_mode?(inst) and inst.agent_last_seen != nil do
      threshold = stale_threshold(inst.push_interval_seconds, push_default, stale_floor)
      age = DateTime.diff(now, inst.agent_last_seen, :second)

      %__MODULE__{
        stale: age > threshold,
        age_seconds: max(age, 0),
        threshold: threshold
      }
    end
  end

  @doc "Seconds of silence tolerated: max(floor, 4 × effective push interval)."
  @spec stale_threshold(integer() | nil, integer(), integer()) :: integer()
  def stale_threshold(push_interval, default, floor) do
    max(floor, @default_missed_pushes * effective_interval(push_interval, default))
  end

  @doc """
  The point after which an instance's cached sections stopped being evidence,
  or nil while it is reporting.

  The hub cache keeps serving the last push/poll forever (it is even rehydrated
  from `status_snapshot` at boot), so a dead box's tunnels still read
  "established". Anything that draws a TIMELINE from that cache needs to know
  where the measurements end — past this timestamp the state is last-known, not
  observed, and must be drawn as unknown rather than as up or down.

  Both transports, same rule as `stale_threshold/3` — `max(floor,
  #{@default_missed_pushes} × cycle)`: a push agent goes silent at
  `agent_last_seen`, a polled box at `last_success_at`. Leaving the poll side
  out would keep painting a dead Securepoint's tunnels green — the VPN page
  deliberately lists polled boxes too. The floor is what keeps one missed
  cycle on a fast (5–15s) poll interval from flipping a whole lane to grey.

  This is deliberately a freshness question, not a reachability one, so it can
  answer "silent" earlier than `Orbit.Instances.status_bucket/3` calls a polled
  box offline (flat 5-minute window). Data being too old to draw and a box
  being declared down are different verdicts.
  """
  @spec silent_since(Instance.t(), t() | nil, integer(), integer(), DateTime.t()) ::
          DateTime.t() | nil
  def silent_since(inst, staleness, poll_default, stale_floor, now)

  def silent_since(%Instance{} = inst, %__MODULE__{stale: true}, _poll_def, _floor, _now),
    do: inst.agent_last_seen

  def silent_since(%Instance{}, %__MODULE__{}, _poll_def, _floor, _now), do: nil

  def silent_since(%Instance{} = inst, nil, poll_default, stale_floor, now) do
    # No staleness struct: a polled box (handled here) or a push agent that has
    # never reported — the latter has no cached sections to grey out at all.
    with false <- Instance.agent_mode?(inst),
         %DateTime{} = last <- inst.last_success_at,
         tolerated = stale_threshold(inst.poll_interval_seconds, poll_default, stale_floor),
         true <- DateTime.diff(now, last) > tolerated do
      last
    else
      _ -> nil
    end
  end

  defp effective_interval(override, _default) when is_integer(override) and override > 0,
    do: override

  defp effective_interval(_override, default), do: default
end
