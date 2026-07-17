defmodule Orbit.Checks.EvaluateTest do
  @moduledoc "Threshold + incident-rule parity with checks/evaluate.py (pure, DB-free)."
  use ExUnit.Case, async: true

  alias Orbit.Checks.Evaluate
  alias Orbit.Checks.ServiceCheck

  describe "memory_check — 80/90 thresholds" do
    test "ok / warn / crit boundaries" do
      assert %ServiceCheck{state: 0, key: "memory"} = Evaluate.memory_check(%{"used_pct" => 79.9})
      assert %ServiceCheck{state: 1} = Evaluate.memory_check(%{"used_pct" => 80.0})
      assert %ServiceCheck{state: 1} = Evaluate.memory_check(%{"used_pct" => 89.9})
      assert %ServiceCheck{state: 2} = Evaluate.memory_check(%{"used_pct" => 90.0})
    end

    test "summary rounds the percent and carries perfdata levels" do
      c = Evaluate.memory_check(%{"used_pct" => 90.4})
      assert c.summary == "Memory 90% used (critical)"
      assert [%{name: "mem_used_pct", value: 90.4, warn: 80.0, crit: 90.0, unit: "%"}] = c.metrics
    end

    test "no memory section → nil (never a check on absent data)" do
      assert Evaluate.memory_check(nil) == nil
      assert Evaluate.memory_check(%{}) == nil
    end
  end

  describe "swap_check — no-data sentinel (swap_total_mb<=0)" do
    test "no swap device → nil (incident c37de13: never crit on absent feature)" do
      assert Evaluate.swap_check(%{"swap_total_mb" => 0.0, "swap_used_pct" => 0.0}) == nil
      assert Evaluate.swap_check(%{"used_pct" => 30.0}) == nil
    end

    test "50/80 thresholds when swap present" do
      assert %ServiceCheck{state: 0} =
               Evaluate.swap_check(%{"swap_total_mb" => 2048.0, "swap_used_pct" => 49.0})

      assert %ServiceCheck{state: 1} =
               Evaluate.swap_check(%{"swap_total_mb" => 2048.0, "swap_used_pct" => 50.0})

      assert %ServiceCheck{state: 2, key: "swap"} =
               Evaluate.swap_check(%{"swap_total_mb" => 2048.0, "swap_used_pct" => 80.0})
    end
  end

  describe "cpu_check — WARN ceiling, never crit" do
    test "ok below 95, warn at/above 95, NEVER crit" do
      assert %ServiceCheck{state: 0} = Evaluate.cpu_check(%{"total_pct" => 94.9})
      assert %ServiceCheck{state: 1} = Evaluate.cpu_check(%{"total_pct" => 95.0})
      # Even pegged at 100 CPU stays WARN — spiky, deliberately can't crit.
      assert %ServiceCheck{state: 1} = Evaluate.cpu_check(%{"total_pct" => 100.0})
    end

    test "raw key is total_pct, nil otherwise" do
      assert Evaluate.cpu_check(%{"total" => 99.0}) == nil
      assert Evaluate.cpu_check(nil) == nil
    end
  end

  describe "disk_checks — size-scaled levels" do
    test "small boot disk uses 80/90 fallback" do
      [c] =
        Evaluate.disk_checks([%{"mountpoint" => "/", "used_pct" => 91.0, "total_mb" => 30_000.0}])

      assert c.state == 2
      assert c.key == "disk:/"
      assert c.summary =~ "GB free"
    end

    test "large 2TB volume tolerates more (93/97), so 91% is still OK" do
      [c] =
        Evaluate.disk_checks([
          %{"mountpoint" => "/data", "used_pct" => 91.0, "total_mb" => 2_097_152.0}
        ])

      assert c.state == 0
    end

    test "unknown total falls back to 80/90" do
      [c] = Evaluate.disk_checks([%{"mountpoint" => "/x", "used_pct" => 85.0}])
      assert c.state == 1
    end

    test "one check per volume" do
      checks =
        Evaluate.disk_checks([
          %{"mountpoint" => "/", "used_pct" => 10.0},
          %{"mountpoint" => "/var", "used_pct" => 20.0}
        ])

      assert length(checks) == 2
      assert Enum.map(checks, & &1.key) == ["disk:/", "disk:/var"]
    end
  end

  describe "load_check — per-core saturation, CRIT allowed" do
    test "no-data sentinel: cores<=0 → nil" do
      assert Evaluate.load_check(%{"five" => 3.0, "cores" => 0}) == nil
      assert Evaluate.load_check(nil) == nil
    end

    test "2/4 per-core thresholds on the 5-min average" do
      assert %ServiceCheck{state: 0} = Evaluate.load_check(%{"five" => 3.9, "cores" => 2})
      assert %ServiceCheck{state: 1} = Evaluate.load_check(%{"five" => 4.0, "cores" => 2})
      # Unlike CPU, load CAN crit: 4x cores.
      assert %ServiceCheck{state: 2, key: "load"} =
               Evaluate.load_check(%{"five" => 8.0, "cores" => 2})
    end
  end

  describe "pf_states_check — no-data sentinel (states_limit<=0)" do
    test "direct-poll box (no state table) → nil" do
      assert Evaluate.pf_states_check(%{
               "states_limit" => 0,
               "states_pct" => 0.0,
               "states_current" => 0
             }) ==
               nil
    end

    test "80/95 fill thresholds" do
      base = %{"states_limit" => 100_000, "states_current" => 50_000}
      assert %ServiceCheck{state: 0} = Evaluate.pf_states_check(Map.put(base, "states_pct", 79.0))
      assert %ServiceCheck{state: 1} = Evaluate.pf_states_check(Map.put(base, "states_pct", 80.0))

      assert %ServiceCheck{state: 2, key: "pf_states"} =
               Evaluate.pf_states_check(Map.put(base, "states_pct", 95.0))
    end
  end

  describe "ntp_check — unsynced is WARN never CRIT" do
    test "no-data sentinel: stratum<0 → nil" do
      assert Evaluate.ntp_check(%{"stratum" => -1}) == nil
      assert Evaluate.ntp_check(nil) == nil
    end

    test "synced → OK, unsynced → WARN (freshly booted box never red)" do
      assert %ServiceCheck{state: 0, key: "ntp"} =
               Evaluate.ntp_check(%{
                 "stratum" => 2,
                 "synced" => true,
                 "offset_ms" => 1.2,
                 "peer" => "a"
               })

      assert %ServiceCheck{state: 1} =
               Evaluate.ntp_check(%{"stratum" => 16, "synced" => false})
    end
  end

  describe "gateway_checks — down word ⇒ CRIT, loss 20/80" do
    test "down status is CRIT regardless of loss" do
      [c] = Evaluate.gateway_checks([%{"name" => "WAN", "status" => "down", "loss" => "0%"}])
      assert c.state == 2
      assert c.key == "gateway:WAN"
      assert c.summary == "Gateway WAN down"
    end

    test "loss thresholds when online" do
      online = fn loss -> %{"name" => "WAN", "status" => "online", "loss" => loss} end
      assert [%ServiceCheck{state: 0}] = Evaluate.gateway_checks([online.("5%")])
      assert [%ServiceCheck{state: 1}] = Evaluate.gateway_checks([online.("20%")])
      assert [%ServiceCheck{state: 2}] = Evaluate.gateway_checks([online.("80%")])
    end

    test "missing loss → no perfdata, still OK when up" do
      [c] = Evaluate.gateway_checks([%{"name" => "WAN", "status" => "online"}])
      assert c.state == 0
      assert c.metrics == []
    end
  end

  describe "severity ordering (UNKNOWN below WARN)" do
    test "CRIT > WARN > UNKNOWN > OK" do
      ranks = Enum.map([2, 1, 3, 0], &ServiceCheck.severity/1)
      assert ranks == [3, 2, 1, 0]
    end
  end

  describe "evaluate/1 over a full cache entry" do
    test "collects non-nil family checks from raw sections" do
      entry = %{
        "status" => %{
          "cpu" => %{"total_pct" => 12.0},
          "memory" => %{"used_pct" => 40.0, "swap_total_mb" => 0.0, "swap_used_pct" => 0.0},
          "disks" => [%{"mountpoint" => "/", "used_pct" => 30.0}]
        }
      }

      keys = entry |> Evaluate.evaluate() |> Enum.map(& &1.key) |> Enum.sort()
      # swap absent (no device) → not emitted.
      assert keys == ["cpu", "disk:/", "memory"]
    end
  end
end
