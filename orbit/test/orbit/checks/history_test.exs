defmodule Orbit.Checks.HistoryTest do
  @moduledoc "Lane math for the check timeline (DB-free; read/3 is proven live)."

  use ExUnit.Case, async: true

  alias Orbit.Checks.History

  @now ~U[2026-07-20 12:00:00Z]

  defp event(minutes_ago, old, new) do
    %{ts: DateTime.add(@now, -minutes_ago * 60), old_state: old, new_state: new, summary: ""}
  end

  test "no recorded transitions is one segment of the live state, not a grey bar" do
    lane = History.lane([], 0, @now)

    # A monitor that has been fine since it was created has no rows at all.
    # Rendering that as "unknown" would read as broken monitoring.
    assert [%{left: +0.0, width: 100.0, state: :up}] = lane.segments
  end

  test "a segment ends where the state it holds changed" do
    # One transition 30 min ago inside the one-hour minimum window: OK for the
    # first half, CRIT for the second. The pre-transition state must be
    # visible — squeezing it out was the whole point of the minimum window.
    lane = History.lane([event(30, 0, 2)], 2, @now)

    assert [first, second] = lane.segments
    assert first.state == :up
    assert_in_delta first.width, 50.0, 0.1
    assert second.state == :down
    assert_in_delta second.left, 50.0, 0.1
  end

  test "the tail takes the live state, not the last recorded one" do
    # Recorded: went CRIT. Live: OK again — the recovery has not been written
    # yet (it lands on the next push). The right edge must show what the box
    # reports now, or the timeline contradicts the row beside it.
    lane = History.lane([event(10, 0, 2)], 0, @now)

    assert List.last(lane.segments).state == :up
  end

  test "events arrive newest-first from the reader and are still ordered" do
    lane = History.lane([event(10, 2, 0), event(40, 0, 2)], 0, @now)

    # Segments come back in PAINT order (OK first), so read the timeline by
    # offset: OK, then the outage a third in, then OK again.
    assert Enum.map(Enum.sort_by(lane.segments, & &1.left), & &1.state) == [:up, :down, :up]
    # The oldest event is inside the hour, so the window keeps its floor.
    assert lane.window_start == DateTime.add(@now, -3600)
  end

  test "WARN is its own colour, and UNKNOWN is not a failure" do
    assert History.state_of(0) == :up
    assert History.state_of(1) == :partial
    assert History.state_of(2) == :down
    assert History.state_of(3) == :unknown
    assert History.state_of(nil) == nil
  end

  test "a short outage in a long window stays visible" do
    # 70 seconds of CRIT inside an 18-day window is 0.005 % — it rounded away
    # to a 0 %-wide div, so the timeline showed solid green over a real
    # outage. Widened to a floor, and painted after the OK stretches so the
    # sliver is on top of the neighbour it now overlaps.
    long_ago = DateTime.add(@now, -18 * 24 * 3600)
    down = %{ts: long_ago, old_state: 0, new_state: 2, summary: ""}
    up = %{ts: DateTime.add(long_ago, 70), old_state: 2, new_state: 0, summary: ""}

    lane = History.lane([down, up], 0, @now)
    outage = Enum.find(lane.segments, &(&1.state == :down))

    assert outage.width >= 0.6
    assert List.last(lane.segments).state == :down
  end

  test "zero-width segments are dropped rather than rendered" do
    # Two transitions in the same second — the segment between them has no
    # width and would otherwise render as a 0%-wide div.
    same = event(20, 0, 1)
    lane = History.lane([same, %{same | old_state: 1, new_state: 2}], 2, @now)

    assert Enum.all?(lane.segments, &(&1.width > 0.0))
  end
end
