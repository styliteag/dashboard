defmodule Orbit.Checks.TransitionsTest do
  @moduledoc """
  Pure ports of the python ingest chain: diff_checks (silent nil baseline,
  missing-key = OK), the flap debounce (3 consecutive fails before a
  non-OK escapes, instant recovery — named-mistake 19) and check_alert.
  The DB/dispatch path is exercised live.
  """

  use ExUnit.Case, async: true

  alias Orbit.Checks.ServiceCheck
  alias Orbit.Checks.Transitions

  defp check(key, state, summary \\ "s") do
    %ServiceCheck{key: key, state: state, summary: summary}
  end

  describe "diff/2" do
    test "nil baseline is silent (restart must not storm)" do
      assert Transitions.diff(nil, [check("cpu", 2)]) == []
    end

    test "missing key in the baseline counts as OK" do
      assert [%{check_key: "swap", old_state: 0, new_state: 1}] =
               Transitions.diff(%{}, [check("swap", 1)])
    end

    test "only changed states produce transitions" do
      prev = %{"cpu" => 1, "memory" => 0}

      assert [%{check_key: "cpu", old_state: 1, new_state: 0}] =
               Transitions.diff(prev, [check("cpu", 0), check("memory", 0)])
    end
  end

  describe "debounce/2" do
    test "flap families hold at OK until 3 consecutive fails" do
      c = check("connectivity:8.8.8.8", 2)

      {out1, s1} = Transitions.debounce([c], %{})
      assert [%ServiceCheck{state: 0}] = out1

      {out2, s2} = Transitions.debounce([c], s1)
      assert [%ServiceCheck{state: 0}] = out2

      {out3, _s3} = Transitions.debounce([c], s2)
      assert [%ServiceCheck{state: 2}] = out3
    end

    test "recovery is immediate and resets the streak" do
      c_fail = check("iface_errors:ix0", 1)
      {_, s1} = Transitions.debounce([c_fail], %{})
      {_, s2} = Transitions.debounce([c_fail], s1)

      # OK passes through untouched and drops the streak entry.
      {[ok], s3} = Transitions.debounce([check("iface_errors:ix0", 0)], s2)
      assert ok.state == 0
      assert s3 == %{}

      # Next failure starts from streak 1 again.
      {[held], _} = Transitions.debounce([c_fail], s3)
      assert held.state == 0
    end

    test "non-flap families pass through unchanged" do
      {[c], streaks} = Transitions.debounce([check("memory", 2)], %{})
      assert c.state == 2
      assert streaks == %{}
    end
  end

  test "check_alert builds icon title, level and the full routing key" do
    t = %{check_key: "gateway:WAN", old_state: 0, new_state: 2, summary: "Gateway WAN down"}

    assert {"🔴 fw1: Gateway WAN down", "Gateway WAN down", "error", "gateway:WAN"} =
             Transitions.check_alert("fw1", t)
  end
end
