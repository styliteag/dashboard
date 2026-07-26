defmodule Orbit.MonitorsMatchTest do
  @moduledoc """
  Phase-2 monitor lookup must key on the selector pair, not the child name.

  strongSwan splits a multi-net child into sibling CHILD_SAs that all share
  one name ("con1"), so a name-only match resolves every sibling to the SAME
  monitor row: the UI showed one monitor on both rows, and "Edit ping" on the
  second Phase 2 silently edited the first one's monitor. The agent already
  matches by selector pair (`_match_monitor`); this pins the Elixir mirror
  the LiveViews use.
  """
  use ExUnit.Case, async: true

  alias Orbit.Monitors

  defp mon(overrides) do
    Map.merge(
      %{
        id: 1,
        tunnel_id: "con1",
        child_name: "con1",
        local_ts: "",
        remote_ts: "",
        source: "",
        destination: "10.0.0.1",
        enabled: true,
        ping_count: 3
      },
      Map.new(overrides)
    )
  end

  test "siblings sharing a child name resolve to their own selector-pinned monitor" do
    m1 = mon(id: 1, local_ts: "10.20.2.0/24", remote_ts: "192.168.100.0/24")
    m2 = mon(id: 2, local_ts: "10.20.2.0/24", remote_ts: "10.242.22.0/24")

    assert %{id: 1} =
             Monitors.match_p2([m1, m2], "con1", "con1", "10.20.2.0/24", "192.168.100.0/24")

    assert %{id: 2} =
             Monitors.match_p2([m1, m2], "con1", "con1", "10.20.2.0/24", "10.242.22.0/24")
  end

  test "a selector-pinned monitor does not leak onto a sibling with another pair" do
    m1 = mon(id: 1, local_ts: "10.20.2.0/24", remote_ts: "192.168.100.0/24")

    assert Monitors.match_p2([m1], "con1", "con1", "10.20.2.0/24", "10.242.22.0/24") == nil
  end

  test "a selector-less monitor still matches by child name (legacy rows)" do
    m = mon(id: 7, child_name: "child-a")

    assert %{id: 7} = Monitors.match_p2([m], "con1", "child-a", "10.0.0.0/24", "10.1.0.0/24")
    assert Monitors.match_p2([m], "con1", "child-b", "10.0.0.0/24", "10.1.0.0/24") == nil
  end

  test "a selector-less whole-tunnel monitor (empty child name) matches any child" do
    m = mon(id: 8, child_name: "")

    assert %{id: 8} = Monitors.match_p2([m], "con1", "anything", "10.0.0.0/24", "10.1.0.0/24")
  end

  test "the selector pin wins over a selector-less name match" do
    loose = mon(id: 1)
    pinned = mon(id: 2, local_ts: "10.20.2.0/24", remote_ts: "10.242.22.0/24")

    assert %{id: 2} =
             Monitors.match_p2([loose, pinned], "con1", "con1", "10.20.2.0/24", "10.242.22.0/24")
  end

  test "another tunnel's monitor never matches" do
    m = mon(id: 9, tunnel_id: "con2", local_ts: "10.20.2.0/24", remote_ts: "10.242.22.0/24")

    assert Monitors.match_p2([m], "con1", "con1", "10.20.2.0/24", "10.242.22.0/24") == nil
  end

  test "nil inputs behave as empty strings" do
    m = mon(id: 3, child_name: "")

    assert %{id: 3} = Monitors.match_p2([m], "con1", nil, nil, nil)
    assert Monitors.match_p2([], "con1", nil, nil, nil) == nil
  end
end
