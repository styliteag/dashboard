defmodule Orbit.AvailabilityTest do
  @moduledoc """
  Pure helper ports (python-parity: metrics/store.is_online, poller/gate
  stale_threshold + is_stale with the restart floor). The DB flip paths are
  proven live against the dev stack.
  """

  use ExUnit.Case, async: true

  alias Orbit.Availability

  @t0 ~N[2026-07-18 12:00:00]

  test "online?: success must exist and be newer than the last error" do
    refute Availability.online?(nil, nil)
    refute Availability.online?(nil, @t0)
    assert Availability.online?(@t0, nil)
    assert Availability.online?(@t0, ~N[2026-07-18 11:00:00])
    refute Availability.online?(~N[2026-07-18 11:00:00], @t0)
  end

  test "stale_threshold scales with the effective push interval, floored" do
    # Global floor wins for fast pushers (4×30=120 == floor 120).
    assert Availability.stale_threshold(30, 60, 120) == 120
    # Slow pusher: ~4 missed pushes beat the floor (300s agent → 1200s).
    assert Availability.stale_threshold(300, 60, 120) == 1200
    # nil/0 interval falls back to the default push interval.
    assert Availability.stale_threshold(nil, 60, 120) == 240
    assert Availability.stale_threshold(0, 60, 120) == 240
  end

  test "stale?: silence beyond threshold, restart floor caps the clock" do
    last_seen = ~N[2026-07-18 11:00:00]
    now = ~N[2026-07-18 12:00:00]
    boot = ~N[2026-07-18 10:00:00]

    assert Availability.stale?(now, last_seen, 120, boot)
    refute Availability.stale?(now, last_seen, 7200, boot)

    # Backend restarted 60s ago: an hour of silence must NOT count —
    # the agent had no chance to reconnect yet (2026-07-12 storm incident).
    recent_boot = ~N[2026-07-18 11:59:00]
    refute Availability.stale?(now, last_seen, 120, recent_boot)
  end
end
