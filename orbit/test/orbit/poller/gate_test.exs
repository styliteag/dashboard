defmodule Orbit.Poller.GateTest do
  @moduledoc """
  Due-gating parity with backend/src/app/poller/gate.py — pure, DB-free.

  The load-bearing property is that gating uses the last ATTEMPT, not the last
  success: a box that is down must retry on its own interval instead of being
  polled on every 10s tick.
  """
  use ExUnit.Case, async: true

  alias Orbit.Poller.Gate

  @now ~U[2026-07-19 12:00:00Z]

  defp ago(seconds), do: DateTime.add(@now, -seconds)
  defp naive_ago(seconds), do: seconds |> ago() |> DateTime.to_naive()

  describe "effective_interval/2" do
    test "a positive per-instance override wins over the global default" do
      assert Gate.effective_interval(300, 30) == 300
    end

    test "nil, zero and negative overrides fall back to the default" do
      assert Gate.effective_interval(nil, 30) == 30
      assert Gate.effective_interval(0, 30) == 30
      assert Gate.effective_interval(-5, 30) == 30
    end
  end

  describe "due?/4" do
    test "a never-attempted instance is due immediately" do
      assert Gate.due?(@now, nil, nil, 30)
    end

    test "not due before its own interval has elapsed" do
      refute Gate.due?(@now, ago(10), nil, 30)
    end

    test "due once the interval has elapsed" do
      assert Gate.due?(@now, ago(30), nil, 30)
      assert Gate.due?(@now, ago(31), nil, 30)
    end

    test "gates on the newest attempt, so a failing box is not hammered" do
      # Last success long ago, error just now: not due — this is the whole
      # point of gating on the attempt rather than the success.
      refute Gate.due?(@now, ago(3600), ago(5), 30)
      # …and it retries once its interval has passed since that error.
      assert Gate.due?(@now, ago(3600), ago(35), 30)
    end

    test "an instance that only ever errored is gated on the error" do
      refute Gate.due?(@now, nil, ago(5), 30)
      assert Gate.due?(@now, nil, ago(45), 30)
    end

    test "MariaDB naive-but-UTC timestamps compare correctly" do
      # Regression 195e9da: an untagged naive datetime read as local time makes
      # a fresh poll look hours old (or in the future) and breaks the gate.
      refute Gate.due?(@now, naive_ago(10), nil, 30)
      assert Gate.due?(@now, naive_ago(40), nil, 30)
    end

    test "a per-instance slow interval really does poll less often" do
      refute Gate.due?(@now, ago(120), nil, Gate.effective_interval(300, 30))
      assert Gate.due?(@now, ago(320), nil, Gate.effective_interval(300, 30))
    end
  end

  describe "last_attempt/2" do
    test "returns the newer of the two outcomes" do
      assert Gate.last_attempt(ago(100), ago(10)) == ago(10)
      assert Gate.last_attempt(ago(10), ago(100)) == ago(10)
    end

    test "nil when the instance was never attempted" do
      assert Gate.last_attempt(nil, nil) == nil
    end
  end
end
