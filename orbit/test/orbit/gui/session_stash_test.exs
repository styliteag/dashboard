defmodule Orbit.GUI.SessionStashTest do
  @moduledoc "gui_session.py port — single-use, TTL-expiring cookie stash."

  use ExUnit.Case, async: true

  alias Orbit.GUI.SessionStash

  test "put then pop returns the cookies exactly once" do
    s = SessionStash.do_put(%{}, "tok", [{"PHPSESSID", "abc"}], 60, 0)
    {pairs, s2} = SessionStash.do_pop(s, "tok", 1_000)
    assert pairs == [{"PHPSESSID", "abc"}]
    # Single-use: a second pop is empty.
    {again, _} = SessionStash.do_pop(s2, "tok", 1_000)
    assert again == []
  end

  test "empty/nameless cookies never stash" do
    s = SessionStash.do_put(%{}, "tok", [{nil, "x"}, {"", "y"}], 60, 0)
    assert s == %{}
  end

  test "an expired entry pops empty and is pruned" do
    s = SessionStash.do_put(%{}, "tok", [{"c", "v"}], 1, 0)
    # 2s later (ttl 1s → expiry at 1000ms), the entry is gone.
    {pairs, s2} = SessionStash.do_pop(s, "tok", 2_000)
    assert pairs == []
    assert s2 == %{}
  end

  test "the running GenServer round-trips a put/pop" do
    pid = start_supervised!({SessionStash, name: nil})
    SessionStash.put(pid, "t1", [{"a", "1"}], 60)
    # cast → allow it to land before the call
    assert SessionStash.pop(pid, "t1") == [{"a", "1"}]
    assert SessionStash.pop(pid, "t1") == []
  end
end
