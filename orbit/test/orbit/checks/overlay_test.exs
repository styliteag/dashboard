defmodule Orbit.Checks.OverlayTest do
  @moduledoc "Staleness + maintenance overlay parity (checks/overlay.py, staleness.py)."
  use ExUnit.Case, async: true

  alias Orbit.Checks.{Overlay, ServiceCheck, Staleness}
  alias Orbit.Instances.Instance

  defp crit(key), do: %ServiceCheck{key: key, state: 2, summary: "#{key} down"}
  defp ok(key), do: %ServiceCheck{key: key, state: 0, summary: "#{key} ok"}

  describe "Staleness.resolve" do
    test "nil for a direct-poll instance (no agent to be stale)" do
      inst = %Instance{transport: "direct", agent_last_seen: ~U[2026-07-17 12:00:00Z]}
      assert Staleness.resolve(inst, 30, 300, ~U[2026-07-17 12:10:00Z]) == nil
    end

    test "nil for a push agent that never reported" do
      inst = %Instance{transport: "push", agent_last_seen: nil}
      assert Staleness.resolve(inst, 30, 300, ~U[2026-07-17 12:10:00Z]) == nil
    end

    test "threshold scales with push interval, floored at agent_stale_seconds" do
      # 4 × 30 = 120 < floor 300 → 300.
      assert Staleness.stale_threshold(30, 30, 300) == 300
      # 4 × 120 = 480 > floor 300 → 480 (a deliberately slow agent isn't flagged early).
      assert Staleness.stale_threshold(120, 30, 300) == 480
    end

    test "fresh vs stale by age against threshold" do
      inst = %Instance{transport: "push", agent_last_seen: ~U[2026-07-17 12:00:00Z]}
      fresh = Staleness.resolve(inst, 30, 300, ~U[2026-07-17 12:02:00Z])
      assert fresh.stale == false
      stale = Staleness.resolve(inst, 30, 300, ~U[2026-07-17 12:10:00Z])
      assert stale.stale == true
      assert stale.threshold == 300
    end
  end

  describe "apply_staleness" do
    test "nil staleness returns checks unchanged (direct poll)" do
      checks = [crit("gateway:WAN")]
      assert Overlay.apply_staleness(checks, nil) == checks
    end

    test "fresh: prepends OK agent service, leaves the rest" do
      s = %Staleness{stale: false, age_seconds: 12, threshold: 300}
      [agent | rest] = Overlay.apply_staleness([crit("x")], s)
      assert agent.key == "agent"
      assert agent.state == 0
      assert rest == [crit("x")]
    end

    test "stale: WARN agent + CRIT capped to WARN (a stale down is a guess)" do
      s = %Staleness{stale: true, age_seconds: 400, threshold: 300}
      [agent, capped] = Overlay.apply_staleness([crit("gateway:WAN")], s)
      assert agent.state == 1
      assert capped.state == 1
      assert capped.summary =~ "stale: agent silent 400s"
    end

    test "stale: OK stays OK (no wall of yellow — only the agent service)" do
      s = %Staleness{stale: true, age_seconds: 400, threshold: 300}
      [_agent, kept] = Overlay.apply_staleness([ok("ntp")], s)
      assert kept.state == 0
    end
  end

  describe "apply_maintenance" do
    test "off is a no-op" do
      checks = [crit("x")]
      assert Overlay.apply_maintenance(checks, false) == checks
    end

    test "on: banner + every check capped at WARN" do
      [banner, capped] = Overlay.apply_maintenance([crit("gateway:WAN")], true)
      assert banner.key == "maintenance"
      assert banner.state == 1
      assert capped.state == 1
      assert capped.summary =~ "(maintenance)"
    end
  end

  describe "overlay/3 — full layering" do
    test "stale + maintenance: maintenance banner first, all capped at WARN" do
      s = %Staleness{stale: true, age_seconds: 400, threshold: 300}
      result = Overlay.overlay([crit("gateway:WAN")], s, true)
      assert hd(result).key == "maintenance"
      assert Enum.all?(result, &(&1.state <= 1))
      assert Enum.map(result, & &1.key) == ["maintenance", "agent", "gateway:WAN"]
    end
  end
end
