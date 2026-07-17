defmodule Orbit.Poller.OpnsenseClientTest do
  @moduledoc "Parse-function parity with xsense/client.py (DB-free; live poll needs lab creds)."
  use ExUnit.Case, async: true

  alias Orbit.Poller.OpnsenseClient, as: C

  describe "cpu_from_resources" do
    test "cpu.used → total_pct" do
      assert C.cpu_from_resources(%{"cpu" => %{"used" => 12.5}}) == %{"total_pct" => 12.5}
      assert C.cpu_from_resources(%{"cpu" => %{"used" => "23"}}) == %{"total_pct" => 23.0}
    end

    test "missing cpu → nil (no section, no bogus check)" do
      assert C.cpu_from_resources(%{}) == nil
      assert C.cpu_from_resources(%{"cpu" => %{}}) == nil
    end
  end

  describe "memory_from_resources" do
    test "prefers *_frmt (MB) and computes used_pct" do
      mem = %{
        "memory" => %{
          "total_frmt" => "4051",
          "used_frmt" => "1783",
          "total" => "x",
          "used" => "y"
        }
      }

      out = C.memory_from_resources(mem)
      assert out["total_mb"] == 4051.0
      assert out["used_mb"] == 1783.0
      assert out["used_pct"] == Float.round(1783 / 4051 * 100, 1)
      # No swap from this endpoint → swap_check will return nil.
      assert out["swap_total_mb"] == 0.0
    end

    test "falls back to bytes when *_frmt absent" do
      mem = %{"memory" => %{"total" => 4_294_967_296, "used" => 2_147_483_648}}
      out = C.memory_from_resources(mem)
      assert_in_delta out["total_mb"], 4096.0, 1.0
      assert_in_delta out["used_pct"], 50.0, 0.5
    end

    test "missing memory → nil" do
      assert C.memory_from_resources(%{}) == nil
    end
  end

  describe "disks_from_systemdisk" do
    test "devices[] → per-mount raw disk section (numeric or '42%')" do
      data = %{
        "devices" => [
          %{"device" => "zroot/ROOT/default", "mountpoint" => "/", "used_pct" => 42},
          %{"device" => "d2", "type" => "/var", "capacity" => "88%"}
        ]
      }

      [root, var] = C.disks_from_systemdisk(data)
      assert root["mountpoint"] == "/"
      assert root["used_pct"] == 42.0
      assert var["mountpoint"] == "/var"
      assert var["used_pct"] == 88.0
    end

    test "bare list and empty both handled" do
      assert C.disks_from_systemdisk([%{"device" => "x", "used_pct" => 10}])
             |> hd()
             |> Map.get("used_pct") ==
               10.0

      assert C.disks_from_systemdisk(nil) == []
    end
  end

  test "the parsed sections feed the checks engine directly" do
    # A direct-poll status is the same raw shape a push agent sends.
    status = %{
      "cpu" => C.cpu_from_resources(%{"cpu" => %{"used" => 96.0}}),
      "memory" =>
        C.memory_from_resources(%{"memory" => %{"total_frmt" => "1000", "used_frmt" => "950"}})
    }

    keys =
      %{"status" => status}
      |> Orbit.Checks.Evaluate.evaluate()
      |> Enum.map(& &1.key)
      |> Enum.sort()

    assert "cpu" in keys
    assert "memory" in keys
    # 95%+ cpu is WARN (never crit), 95% mem is CRIT — proves the shapes match.
    checks =
      %{"status" => status} |> Orbit.Checks.Evaluate.evaluate() |> Map.new(&{&1.key, &1.state})

    assert checks["cpu"] == 1
    assert checks["memory"] == 2
  end
end
