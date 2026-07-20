defmodule Orbit.Ipsec.HistoryTest do
  @moduledoc "Tunnel transition diff (ipsec/history.py parity) on raw agent maps."
  use ExUnit.Case, async: true

  alias Orbit.Ipsec.History

  defp tunnel(attrs) do
    Map.merge(
      %{
        "id" => "con1",
        "status" => "established",
        "phase2_up" => 1,
        "phase2_total" => 1,
        "children" => []
      },
      attrs
    )
  end

  test "phase1 up/down flips produce phase1_up / phase1_down" do
    assert [%{event_type: "phase1_down", old_value: "established", new_value: "down"}] =
             History.diff([tunnel(%{})], [tunnel(%{"status" => "down"})])

    assert [%{event_type: "phase1_up"}] =
             History.diff([tunnel(%{"status" => "down"})], [tunnel(%{})])
  end

  test "same up-ness but different wording is phase1_changed" do
    assert [%{event_type: "phase1_changed"}] =
             History.diff([tunnel(%{"status" => "established"})], [
               tunnel(%{"status" => "installed"})
             ])
  end

  test "phase2 count changes produce phase2_changed with x/n values" do
    assert [%{event_type: "phase2_changed", old_value: "1/1", new_value: "0/1"}] =
             History.diff([tunnel(%{})], [tunnel(%{"phase2_up" => 0})])
  end

  test "ping transitions: ok/fail recorded, none and unchanged skipped" do
    child = fn state ->
      [
        %{
          "name" => "c1",
          "local_ts" => "10.0.0.0/24",
          "remote_ts" => "10.1.0.0/24",
          "ping_state" => state
        }
      ]
    end

    assert [%{event_type: "ping_fail", child_name: "c1"}] =
             History.diff(
               [tunnel(%{"children" => child.("ok")})],
               [tunnel(%{"children" => child.("fail")})]
             )

    assert [] =
             History.diff(
               [tunnel(%{"children" => child.("ok")})],
               [tunnel(%{"children" => child.("none")})]
             )

    assert [] =
             History.diff(
               [tunnel(%{"children" => child.("ok")})],
               [tunnel(%{"children" => child.("ok")})]
             )
  end

  test "unknown tunnels and nil baselines never diff" do
    assert History.diff(nil, [tunnel(%{})]) == []
    assert History.diff([tunnel(%{"id" => "other"})], [tunnel(%{"status" => "down"})]) == []
  end

  test "record is a no-op on an empty diff" do
    assert History.record(1, DateTime.utc_now(), []) == 0
  end

  describe "annotate_dup/2 (3-push streak)" do
    defp dup_push(count) do
      %{
        "ipsec" => %{
          "tunnels" => [
            tunnel(%{
              "children" => [
                %{"name" => "c1", "local_ts" => "a", "remote_ts" => "b", "dup_count" => count}
              ]
            })
          ]
        }
      }
    end

    defp child_of({data, _streaks}) do
      data["ipsec"]["tunnels"] |> hd() |> Map.get("children") |> hd()
    end

    test "flag lights only after three consecutive duplicated pushes" do
      {_, s1} = History.annotate_dup(dup_push(3), %{})
      {_, s2} = History.annotate_dup(dup_push(3), s1)
      r3 = History.annotate_dup(dup_push(3), s2)

      refute child_of(History.annotate_dup(dup_push(3), %{}))["phase2_dup_persistent"]
      refute child_of(History.annotate_dup(dup_push(3), s1))["phase2_dup_persistent"]
      assert child_of(r3)["phase2_dup_persistent"]
    end

    test "a clean push resets the streak; missing ipsec keeps streaks" do
      {_, s1} = History.annotate_dup(dup_push(3), %{})
      {_, s2} = History.annotate_dup(dup_push(3), s1)
      # clean push → selector drops out
      {_, s3} = History.annotate_dup(dup_push(1), s2)
      assert s3 == %{}
      # collector failure (no ipsec) → streaks survive untouched
      {data, s4} = History.annotate_dup(%{"cpu" => %{}}, s2)
      assert s4 == s2
      assert data == %{"cpu" => %{}}
    end
  end

  test "dup flag flips diff into phase2_dup_on/off with the selector pair" do
    child = fn dup ->
      [
        %{
          "name" => "c1",
          "local_ts" => "10.0.0.0/24",
          "remote_ts" => "10.1.0.0/24",
          "ping_state" => "none",
          "dup_count" => 3,
          "phase2_dup_persistent" => dup
        }
      ]
    end

    assert [
             %{
               event_type: "phase2_dup_on",
               old_value: "10.0.0.0/24 → 10.1.0.0/24",
               new_value: "3× SAs"
             }
           ] =
             History.diff(
               [tunnel(%{"children" => child.(false)})],
               [tunnel(%{"children" => child.(true)})]
             )

    assert [%{event_type: "phase2_dup_off", new_value: "resolved"}] =
             History.diff(
               [tunnel(%{"children" => child.(true)})],
               [tunnel(%{"children" => child.(false)})]
             )
  end

  describe "lanes/3 (graph)" do
    defp ev(kind, minutes_ago, new_value \\ "") do
      %{
        ts: DateTime.add(~U[2026-07-18 12:00:00Z], -minutes_ago * 60),
        event_type: kind,
        old_value: "",
        new_value: new_value,
        child_name: ""
      }
    end

    test "phase1 lane: recorded flips cut segments, live state takes the tail" do
      now = ~U[2026-07-18 12:00:00Z]
      # up at -100min (window start), down at -50min, live is up again.
      events = [ev("phase1_down", 50), ev("phase1_up", 100)]
      %{phase1: lane} = History.lanes(events, %{up: true, phase2_up: 1, phase2_total: 1}, now)

      # zero-width unknown head is dropped; the tail takes the LIVE state.
      assert Enum.map(lane, & &1.state) == [:up, :up]
      assert [%{left: +0.0, width: 50.0}, %{left: 50.0, width: 50.0}] = lane
    end

    test "phase2 lane: three cuts parse x/n into up/partial/down" do
      now = ~U[2026-07-18 12:00:00Z]

      events = [
        ev("phase2_changed", 90, "2/2"),
        ev("phase2_changed", 60, "1/2"),
        ev("phase2_changed", 30, "0/2")
      ]

      %{phase2: lane} = History.lanes(events, %{up: true, phase2_up: 0, phase2_total: 2}, now)
      assert Enum.map(lane, & &1.state) == [:up, :partial, :down]
    end

    test "no events: one full-width segment per lane, live where known" do
      now = ~U[2026-07-18 12:00:00Z]

      %{phase1: p1, ping: ping} =
        History.lanes([], %{up: false, phase2_up: 0, phase2_total: 0}, now)

      assert [%{left: +0.0, width: 100.0, state: :down}] = p1
      assert [%{state: :unknown}] = ping
    end
  end

  describe "lanes/4 with a fixed window (the 24h/7d/30d selector)" do
    @now ~U[2026-07-18 12:00:00Z]

    defp evt(kind, hours_ago, new_value \\ "") do
      %{
        ts: DateTime.add(@now, -hours_ago * 3600),
        event_type: kind,
        old_value: "",
        new_value: new_value,
        child_name: ""
      }
    end

    test "the state before the window is carried in, not thrown away" do
      # A tunnel that went up a week ago and has not changed since must show a
      # 24h view that is green end to end. Filtering the older event away
      # would open every window with a grey "no data" stretch.
      events = [evt("phase1_up", 168)]
      window = DateTime.add(@now, -24 * 3600)

      %{phase1: lane} =
        History.lanes(events, %{up: true, phase2_up: 1, phase2_total: 1}, @now, window)

      assert [%{left: +0.0, width: 100.0, state: :up}] = lane
    end

    test "the window fixes the left edge regardless of the oldest event" do
      events = [evt("phase1_down", 12)]
      window = DateTime.add(@now, -24 * 3600)

      %{window_start: start, phase1: lane} =
        History.lanes(events, %{up: false, phase2_up: 0, phase2_total: 1}, @now, window)

      assert start == window
      # Half the window before the drop, half after.
      assert [%{width: w1}, %{width: w2}] = lane
      assert_in_delta w1, 50.0, 0.1
      assert_in_delta w2, 50.0, 0.1
    end

    test "a two-minute drop inside a 30d window stays visible" do
      # 2 minutes of 43200 is 0.005 % — a 0 %-wide div. The fleet graph exists
      # to show exactly this, so it must not round the outage away.
      events = [evt("phase1_down", 240), evt("phase1_up", 239)]
      window = DateTime.add(@now, -30 * 24 * 3600)

      %{phase1: lane} =
        History.lanes(events, %{up: true, phase2_up: 1, phase2_total: 1}, @now, window)

      down = Enum.find(lane, &(&1.state == :down))
      assert down.width >= 0.6
      # …and painted after the up stretches, so the sliver is on top.
      assert List.last(lane).state == :down
    end

    test "window_start/2 is shared so both pages mean the same by \"7d\"" do
      assert History.window_start("24h", @now) == DateTime.add(@now, -86_400)
      assert History.window_start("7d", @now) == DateTime.add(@now, -604_800)
      assert History.window_start("30d", @now) == DateTime.add(@now, -2_592_000)
      assert History.window_start("all", @now) == nil
    end
  end

  describe "phase2_numeric/4" do
    test "carries the actual counts, ending on the live one" do
      # The colour lane says "partial" whether one of two child SAs dropped or
      # one of eight; the operator's next question is how many of how many.
      events = [
        evt("phase2_changed", 12, "8/8"),
        evt("phase2_changed", 6, "7/8")
      ]

      segs = History.phase2_numeric(events, %{phase2_up: 7, phase2_total: 8}, @now)

      assert Enum.map(segs, & &1.label) == ["8/8", "7/8"]
      assert Enum.all?(segs, &(&1.width > 0))
    end

    test "a stretch with no known count is left out rather than labelled zero" do
      segs = History.phase2_numeric([], %{phase2_up: 2, phase2_total: 2}, @now)
      assert [%{label: "2/2", left: +0.0, width: 100.0}] = segs
    end
  end
end
