defmodule Orbit.Checks.History do
  @moduledoc """
  The recorded state transitions of ONE check, read back for a timeline.

  `Orbit.Checks.Transitions` has been writing `check_events` since the
  cutover — every check that changes state leaves a row — but nothing read
  them per check. The only reader was a private helper on the detail page
  that pulled the last 20 events of an instance across ALL its checks, so
  "when did this monitor actually go down, and how often?" had no answer
  anywhere in the UI.

  Shaped after `Orbit.Ipsec.History` (same table-plus-lane split), but with
  a single lane: a check has one state, not three phases.

  Read-only, and never raises — a timeline is a nicety and must not take a
  page down with it.
  """

  @doc """
  Most-recent-first transitions of one check (capped; ix_check_event_lookup).

  `check_key` is the check's stable key, e.g. `"connectivity:12"`.
  """
  @spec read(integer(), String.t(), pos_integer()) :: [map()]
  def read(instance_id, check_key, limit \\ 100) when is_integer(limit) and limit > 0 do
    Orbit.Repo.query!(
      "SELECT ts, old_state, new_state, summary FROM check_events " <>
        "WHERE instance_id = ? AND check_key = ? ORDER BY ts DESC, id DESC LIMIT #{limit}",
      [instance_id, check_key]
    ).rows
    |> Enum.map(fn [ts, old, new, summary] ->
      %{
        ts: DateTime.from_naive!(ts, "Etc/UTC"),
        old_state: old,
        new_state: new,
        summary: summary
      }
    end)
  rescue
    _ -> []
  catch
    # A pool checkout exits rather than raising; without this an empty
    # timeline would take the whole page down with it.
    _kind, _reason -> []
  end

  @doc """
  Recorded transitions of MANY instances' checks under one key prefix
  (fleet timeline), grouped by `{instance_id, check_key}` with the same
  event shape `read/3` returns. `lane/4` sorts its input, so only the
  grouping matters here. The prefix is bound via `CONCAT(?, '%')` so it
  stays a parameter even though every caller today passes a constant.
  """
  @spec read_many([integer()], String.t(), DateTime.t(), pos_integer()) :: map()
  def read_many(instance_ids, key_prefix, since, limit \\ 5_000)

  def read_many([], _key_prefix, _since, _limit), do: %{}

  def read_many(instance_ids, key_prefix, %DateTime{} = since, limit)
      when is_integer(limit) and limit > 0 do
    placeholders = Enum.map_join(instance_ids, ", ", fn _ -> "?" end)

    Orbit.Repo.query!(
      "SELECT instance_id, check_key, ts, old_state, new_state FROM check_events " <>
        "WHERE instance_id IN (#{placeholders}) AND check_key LIKE CONCAT(?, '%') " <>
        "AND ts >= ? ORDER BY ts LIMIT #{limit}",
      instance_ids ++ [key_prefix, since]
    ).rows
    |> Enum.group_by(
      fn [iid, key | _] -> {iid, key} end,
      fn [_iid, _key, ts, old, new] ->
        %{ts: DateTime.from_naive!(ts, "Etc/UTC"), old_state: old, new_state: new, summary: nil}
      end
    )
  rescue
    _ -> %{}
  catch
    _kind, _reason -> %{}
  end

  @doc "Fleet-graph windows (VPN-page parity); unknown keys mean 'auto'."
  @spec window_start(String.t(), DateTime.t()) :: DateTime.t() | nil
  def window_start("24h", now), do: DateTime.add(now, -24 * 3600)
  def window_start("7d", now), do: DateTime.add(now, -7 * 24 * 3600)
  def window_start("30d", now), do: DateTime.add(now, -30 * 24 * 3600)
  def window_start(_other, _now), do: nil

  @doc """
  One state lane for the graph: `%{window_start, segments}` where each
  segment is `%{left, width, state}` in percent of the window.

  Without an explicit `window_start`: oldest recorded transition → now, but
  at least an hour. Starting exactly at the oldest transition would give the
  state the check was in BEFORE it zero width, so a monitor with one
  recorded outage rendered as a bar that was red from end to end — the "it
  was fine until 09:14" half, the only part worth seeing, was the part that
  got squeezed out.

  With an explicit `window_start` (fleet graph: every lane shares the
  window so outages line up as vertical stripes), events before the window
  are not discarded — the LAST one is what the check was doing when the
  window opened (the Ipsec.History.lanes/4 rule).

  The trailing segment takes the check's LIVE state rather than the last
  recorded one, so the right edge is always what the box reports right now: a
  recovery lands in the table one push after it happened, and a check that has
  never changed state has no rows at all.
  """
  @spec lane([map()], integer() | nil, DateTime.t(), DateTime.t() | nil) :: map()
  def lane(events, live_state, now, window_start \\ nil)

  def lane(events, live_state, %DateTime{} = now, explicit_start) do
    all = Enum.sort_by(events, & &1.ts, DateTime)
    hour_ago = DateTime.add(now, -3600)

    {before, sorted} =
      case explicit_start do
        nil -> {[], all}
        ws -> Enum.split_with(all, &(DateTime.compare(&1.ts, ws) == :lt))
      end

    window_start =
      cond do
        explicit_start -> explicit_start
        sorted != [] -> Enum.min([hd(sorted).ts, hour_ago], DateTime)
        true -> hour_ago
      end

    span = max(DateTime.diff(now, window_start), 1)
    x = fn ts -> min(max(DateTime.diff(ts, window_start) / span * 100, 0.0), 100.0) end

    # Each row records the state the check moved INTO, so the segment that
    # ENDS at a row carries that row's old_state.
    cuts = for e <- sorted, do: {x.(e.ts), state_of(e.new_state)}

    first_state =
      cond do
        before != [] -> state_of(List.last(before).new_state)
        sorted != [] -> state_of(hd(sorted).old_state)
        true -> state_of(live_state)
      end

    {segments, last_left, last_state} =
      Enum.reduce(cuts, {[], 0.0, first_state}, fn {cut, state}, {acc, left, cur} ->
        {[%{left: left, width: cut - left, state: cur} | acc], cut, state}
      end)

    tail = state_of(live_state) || last_state
    all = Enum.reverse([%{left: last_left, width: 100.0 - last_left, state: tail} | segments])

    segments =
      all
      |> Enum.reject(&(&1.width <= 0.0))
      |> Enum.map(&widen/1)
      |> Enum.sort_by(&rank/1)

    %{window_start: window_start, segments: segments}
  end

  # A 70-second outage inside an 18-day window is 0.005 % wide and rounds away
  # to nothing — the one thing the operator opened the timeline to see. Give
  # every segment a floor, and paint the non-OK ones last so a widened sliver
  # is not covered by the neighbouring OK stretch it now overlaps.
  @min_width 0.6

  defp widen(%{width: w} = seg) when w < @min_width, do: %{seg | width: @min_width}
  defp widen(seg), do: seg

  defp rank(%{state: :up}), do: 0
  defp rank(_), do: 1

  @doc "Checkmk state to lane colour: WARN is amber, UNKNOWN is grey, not red."
  @spec state_of(integer() | nil) :: :up | :partial | :down | :unknown | nil
  def state_of(0), do: :up
  def state_of(1), do: :partial
  def state_of(2), do: :down
  def state_of(3), do: :unknown
  def state_of(_), do: nil

  @doc "Human label for a recorded state, for the transition table."
  @spec state_label(integer() | nil) :: String.t()
  def state_label(0), do: "OK"
  def state_label(1), do: "WARN"
  def state_label(2), do: "CRIT"
  def state_label(3), do: "UNKNOWN"
  def state_label(_), do: "—"
end
