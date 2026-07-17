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

  defp effective_interval(override, _default) when is_integer(override) and override > 0,
    do: override

  defp effective_interval(_override, default), do: default
end
