defmodule Orbit.Securepoint.MetricsTest do
  @moduledoc """
  Metric derivation parity with the python client (`securepoint/client.py`
  `_cpu`/`_memory`/`_disks`/`_interfaces`).

  Regression: the port fetched `appmgmt get_information` and passed the raw
  payload through as the "system" section. That endpoint carries none of the
  live stats, so a Securepoint box rendered with no CPU, memory, disk, uptime or
  interface data at all — while the python client had filled the same metrics
  surface as OPNsense since day one.

  `_SYSTEM_INFO` / `_INTERFACE_ADDRS` below are the payloads live-captured from a
  real box in the deleted `backend/tests/test_securepoint_client.py`; the
  expected numbers are what the python code produced from them.
  """
  use ExUnit.Case, async: true

  alias Orbit.Securepoint.Client, as: C

  @system_info [
    %{"attribute" => "hostname", "value" => "fw1.example.net"},
    %{"attribute" => "version", "value" => "14.1.6"},
    %{"attribute" => "Idle", "value" => "  98%"},
    %{"attribute" => "Mem Total", "value" => "3887616"},
    %{"attribute" => "Mem Avail", "value" => "2930392"},
    %{"attribute" => "storage", "value" => "61660659712"},
    %{"attribute" => "storage free", "value" => "57942274048"},
    %{"attribute" => "Uptime", "value" => "01:19:44"},
    %{"attribute" => "productname", "value" => "RC100-G5"},
    %{"attribute" => "cur", "value" => "14.1.6"},
    %{"attribute" => "new", "value" => "none"}
  ]

  @interface_addrs [
    %{"id" => 3, "flags" => ["ONLINE"], "device" => "A1", "address" => "10.21.0.1/22"},
    %{"id" => 0, "flags" => ["DYNAMIC"], "device" => "wan0", "address" => "203.0.113.10/32"}
  ]

  defp info, do: C.flatten_info(@system_info)

  test "flattens the attribute/value rows" do
    assert info()["hostname"] == "fw1.example.net"
    assert info()["Idle"] == "  98%"
  end

  describe "num/1" do
    test "strips padding and the percent sign" do
      assert C.num("  98%") == 98.0
      assert C.num("3887616") == 3_887_616.0
    end

    test "junk degrades to 0.0 instead of raising" do
      assert C.num("n/a") == 0.0
      assert C.num(nil) == 0.0
    end
  end

  test "cpu busy is 100 minus idle" do
    assert C.cpu_from_info(info()) == %{"total_pct" => 2.0}
  end

  test "no Idle attribute means no cpu section (not a zero reading)" do
    refute C.cpu_from_info(%{"hostname" => "x"})
  end

  test "memory from Mem Total / Mem Avail in KiB" do
    mem = C.memory_from_info(info())

    assert mem["total_mb"] == 3796.5
    assert mem["used_mb"] == 934.8
    assert mem["used_pct"] == 24.6
    # No swap on this endpoint — the sentinel keeps swap_check silent.
    assert mem["swap_total_mb"] == 0.0
  end

  describe "swap (derived, not assumed)" do
    test "a box without a swap device keeps the no-data sentinel" do
      assert C.swap_from_info(%{"Swap Total" => "0", "Swap Free" => "0"}) ==
               %{"swap_total_mb" => 0.0, "swap_used_pct" => 0.0}
    end

    test "a box WITH swap is measured — the sentinel must not be hardcoded" do
      s = C.swap_from_info(%{"Swap Total" => "2097152", "Swap Free" => "1048576"})

      assert s["swap_total_mb"] == 2048.0
      assert s["swap_used_pct"] == 50.0
    end

    test "an absent swap attribute is no data, not zero usage of something" do
      assert C.swap_from_info(%{})["swap_total_mb"] == 0.0
    end
  end

  describe "loadavg" do
    test "parses the comma-separated triple and the core count" do
      load = C.loadavg_from_info(%{"loadavg" => "0.42, 0.31, 0.28", "CPU Cores" => "4"})

      assert load == %{"one" => 0.42, "five" => 0.31, "fifteen" => 0.28, "cores" => 4}
    end

    test "an idle box still reports real zeros" do
      assert C.loadavg_from_info(%{"loadavg" => "0.00, 0.00, 0.00"})["one"] == 0.0
    end

    test "no loadavg attribute means NO section — not a fabricated zero" do
      refute C.loadavg_from_info(%{"hostname" => "x"})
      refute C.loadavg_from_info(%{"loadavg" => "garbage"})
    end

    test "the core count is omitted when the box does not report it" do
      load = C.loadavg_from_info(%{"loadavg" => "1.0, 2.0, 3.0"})

      refute Map.has_key?(load, "cores")
    end
  end

  test "no memory section when the box reports no total" do
    refute C.memory_from_info(%{"Mem Total" => "0"})
  end

  test "disks from storage / storage free in bytes" do
    assert [disk] = C.disks_from_info(info())
    assert disk["device"] == "/data"
    assert disk["mountpoint"] == "/data"
    assert disk["used_pct"] == 6.0
    assert disk["total_mb"] == 58804.2
  end

  test "no storage attribute yields no disks" do
    assert C.disks_from_info(%{}) == []
  end

  test "system section prefers hostname/version over the product fields" do
    assert C.system_from_info(info()) == %{"hostname" => "fw1.example.net", "os" => "14.1.6"}
  end

  test "system section falls back to productname" do
    assert %{"hostname" => "RC100-G5"} = C.system_from_info(%{"productname" => "RC100-G5"})
  end

  test "nothing identifying means no system section" do
    refute C.system_from_info(%{"Idle" => "1%"})
  end

  test "interfaces: ONLINE and DYNAMIC both count as up" do
    [a1, wan0] = Enum.map(@interface_addrs, &C.interface_row/1)

    assert a1 == %{
             "name" => "A1",
             "status" => "up",
             "address" => "10.21.0.1/22",
             "bytes_received" => 0,
             "bytes_transmitted" => 0
           }

    assert wan0["name"] == "wan0"
    assert wan0["status"] == "up"
  end

  test "an interface without those flags is down" do
    assert %{"status" => "down"} = C.interface_row(%{"device" => "eth9", "flags" => []})
  end

  test "uptime is carried through verbatim" do
    assert info()["Uptime"] == "01:19:44"
  end
end
