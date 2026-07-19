defmodule Orbit.Poller.Gate do
  @moduledoc """
  Pure due-gating for the direct-poll scheduler — 1:1 port of
  `backend/src/app/poller/gate.py` (the poll half; the push/staleness half of
  that file lives in `Orbit.Availability`).

  The scheduler ticks at a fixed small cadence (`poll_tick_seconds`) and asks
  this module per instance whether its own effective interval has elapsed. That
  is what lets every box run at its own rate — a global default plus an
  optional per-instance override — without one timer per instance.

  Gating is on the **last attempt**, not the last success: a box that is down
  retries on its own interval instead of being hammered every tick.

  MariaDB DATETIME columns read back naive-but-UTC; every timestamp is tagged
  before arithmetic (CLAUDE.md time rule, incident 195e9da).
  """

  @doc "Per-instance override when set to a positive value, else the global default."
  @spec effective_interval(integer() | nil, integer()) :: integer()
  def effective_interval(override, _default)
      when is_integer(override) and override > 0,
      do: override

  def effective_interval(_override, default), do: default

  @doc "Newest of the two poll outcomes as a DateTime, or nil if never attempted."
  @spec last_attempt(term(), term()) :: DateTime.t() | nil
  def last_attempt(last_success_at, last_error_at) do
    [last_success_at, last_error_at]
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&as_utc/1)
    |> case do
      [] -> nil
      stamps -> Enum.max(stamps, DateTime)
    end
  end

  @doc """
  True when the instance's effective interval has elapsed since the last
  attempt. A never-attempted instance is always due (first tick after boot
  picks up a freshly created box).
  """
  @spec due?(DateTime.t(), term(), term(), integer()) :: boolean()
  def due?(now, last_success_at, last_error_at, interval_seconds) do
    case last_attempt(last_success_at, last_error_at) do
      nil -> true
      last -> DateTime.diff(as_utc(now), last) >= interval_seconds
    end
  end

  defp as_utc(%NaiveDateTime{} = naive), do: DateTime.from_naive!(naive, "Etc/UTC")
  defp as_utc(%DateTime{} = dt), do: dt
end
