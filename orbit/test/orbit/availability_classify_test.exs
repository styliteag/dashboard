defmodule Orbit.AvailabilityClassifyTest do
  @moduledoc """
  `Availability.classify/3` — the one availability state machine the fleet
  list tiles, row badges and (pro) host summaries read. Push boxes follow the
  live WS connection; polled boxes the 5-minute success/error window.
  """
  use ExUnit.Case, async: true

  alias Orbit.Availability
  alias Orbit.Instances.Instance

  @now ~U[2026-07-18 12:00:00Z]

  defp ago(seconds), do: seconds && DateTime.add(@now, -seconds)

  defp inst(transport, success, error, last_seen) do
    %Instance{
      transport: transport,
      last_success_at: ago(success),
      last_error_at: ago(error),
      agent_last_seen: ago(last_seen)
    }
  end

  describe "classify/3" do
    # {name, transport, success_ago, error_ago, agent_last_seen_ago, connected?, expected}
    for {name, transport, succ, err, seen, conn, expected} <- [
          {"push connected, never stamped", "push", nil, nil, nil, true, :online},
          {"push connected, error newer", "push", 600, 60, 600, true, :online},
          {"push disconnected, fresh success", "push", 10, nil, 10, false, :offline},
          {"push disconnected, never seen", "push", nil, nil, nil, false, :offline},
          {"polled never polled", "direct", nil, nil, nil, false, :offline},
          {"polled fresh success, no error", "direct", 60, nil, nil, false, :online},
          {"polled fresh success, older error", "direct", 60, 120, nil, false, :online},
          {"polled success exactly at cutoff", "direct", 300, nil, nil, false, :online},
          {"polled success just past cutoff", "direct", 301, nil, nil, false, :offline},
          {"polled fresh success, newer fresh error", "direct", 120, 60, nil, false, :degraded},
          {"polled success and error same instant", "direct", 60, 60, nil, false, :degraded},
          {"polled stale success, fresh error", "direct", 600, 60, nil, false, :offline},
          {"polled only errors", "direct", nil, 60, nil, false, :offline},
          {"polled ignores the WS flag", "direct", 600, nil, nil, true, :offline},
          {"relay is polled too", "relay", 60, nil, nil, false, :online}
        ] do
      test name do
        i = inst(unquote(transport), unquote(succ), unquote(err), unquote(seen))
        assert Availability.classify(i, unquote(conn), @now) == unquote(expected)
      end
    end
  end

  test "online?/2 accepts DateTime as well as NaiveDateTime" do
    assert Availability.online?(ago(10), ago(20))
    refute Availability.online?(ago(20), ago(10))
    refute Availability.online?(ago(10), ago(10))
  end
end
