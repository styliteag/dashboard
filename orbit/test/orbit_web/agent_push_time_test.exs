defmodule OrbitWeb.AgentPushTimeTest do
  @moduledoc """
  The agent's push `ts` stamps agent_last_seen / last_success_at. A box
  clock (or a forged ts) in the FUTURE would keep the box "online" long
  after it went silent, so a ts more than 60 s ahead is replaced by the
  server clock. Past/slightly-skewed timestamps are kept unchanged — whether
  to go server-time-only is an open product decision.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.AgentSocket

  @now ~U[2026-11-08 12:00:00Z]

  test "a far-future ts is clamped to the server clock" do
    assert AgentSocket.push_time("2030-01-01T00:00:00Z", @now) == @now
  end

  test "small skew and past ts are kept" do
    assert AgentSocket.push_time("2026-11-08T12:00:30Z", @now) == ~U[2026-11-08 12:00:30Z]
    assert AgentSocket.push_time("2026-11-08T11:59:00Z", @now) == ~U[2026-11-08 11:59:00Z]
  end

  test "missing or garbage ts is the server clock" do
    assert AgentSocket.push_time(nil, @now) == @now
    assert AgentSocket.push_time("yesterday", @now) == @now
  end
end
