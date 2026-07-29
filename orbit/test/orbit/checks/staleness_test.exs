defmodule Orbit.Checks.StalenessTest do
  @moduledoc """
  `silent_since/4` — the point after which an instance's cached sections stop
  being evidence. Both transports, because a dead Securepoint freezes its
  tunnels exactly like a silent agent does.
  """
  use ExUnit.Case, async: true

  alias Orbit.Checks.Staleness
  alias Orbit.Instances.Instance

  @now ~U[2026-07-18 12:00:00Z]
  @poll_default 30
  @stale_floor 120

  defp push(last_seen, interval \\ 60) do
    %Instance{transport: "push", agent_last_seen: last_seen, push_interval_seconds: interval}
  end

  defp polled(last_success, interval \\ 60) do
    %Instance{
      transport: "direct",
      last_success_at: last_success,
      poll_interval_seconds: interval
    }
  end

  defp resolve(inst), do: Staleness.resolve(inst, 60, 300, @now)

  describe "silent_since/5 —push instances" do
    test "a fresh agent is not silent" do
      inst = push(DateTime.add(@now, -30))
      assert Staleness.silent_since(inst, resolve(inst), @poll_default, @stale_floor, @now) == nil
    end

    test "a stale agent is silent from its last push, not from the threshold" do
      last = DateTime.add(@now, -3600)
      inst = push(last)

      assert Staleness.silent_since(inst, resolve(inst), @poll_default, @stale_floor, @now) ==
               last
    end

    test "an agent that never reported has no cached sections to date" do
      inst = push(nil)
      assert Staleness.silent_since(inst, resolve(inst), @poll_default, @stale_floor, @now) == nil
    end
  end

  describe "silent_since/5 —polled instances" do
    test "a recently polled box is not silent" do
      inst = polled(DateTime.add(@now, -90))
      assert Staleness.silent_since(inst, resolve(inst), @poll_default, @stale_floor, @now) == nil
    end

    test "a box whose poller stopped is silent from its last success" do
      # 4 × 60s poll interval tolerated, same missed-cycles rule as push.
      last = DateTime.add(@now, -1800)
      inst = polled(last)

      assert Staleness.silent_since(inst, resolve(inst), @poll_default, @stale_floor, @now) ==
               last
    end

    test "the tolerance scales with the instance's own poll interval" do
      last = DateTime.add(@now, -1000)
      # 4 × 600s = 2400s tolerated: 1000s of silence is still inside it.
      assert Staleness.silent_since(polled(last, 600), nil, @poll_default, @stale_floor, @now) ==
               nil

      # 4 × 60s = 240s: the same gap is well past it.
      assert Staleness.silent_since(polled(last, 60), nil, @poll_default, @stale_floor, @now) ==
               last
    end

    test "the floor keeps one missed poll on a fast interval from greying a lane" do
      # 4 × 15s would be 60s — a single hiccup. The floor is why it isn't.
      inst = polled(DateTime.add(@now, -100), 15)
      assert Staleness.silent_since(inst, nil, @poll_default, @stale_floor, @now) == nil
    end

    test "a box that never polled successfully has no date to fall back to" do
      inst = polled(nil)
      assert Staleness.silent_since(inst, resolve(inst), @poll_default, @stale_floor, @now) == nil
    end
  end
end
