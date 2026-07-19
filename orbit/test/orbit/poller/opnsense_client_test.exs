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

defmodule Orbit.Poller.OpnsenseClientFetchTest do
  @moduledoc "Full fetch_status against a mocked OPNsense API (Req.Test plug — no real box)."
  use ExUnit.Case, async: true

  alias Orbit.Poller.OpnsenseClient, as: C

  test "fetch_status routes both endpoints through parse into raw sections" do
    Req.Test.stub(Orbit.Poller.OpnsenseClient, fn conn ->
      body =
        case conn.request_path do
          "/api/diagnostics/system/systemResources" ->
            %{
              "cpu" => %{"used" => 42.0},
              "memory" => %{"total_frmt" => "2000", "used_frmt" => "500"}
            }

          "/api/diagnostics/system/systemDisk" ->
            %{"devices" => [%{"device" => "z", "mountpoint" => "/", "used_pct" => 61}]}

          _ ->
            %{}
        end

      Req.Test.json(conn, body)
    end)

    client = %C{
      base_url: "https://box.example:4444",
      api_key: "k",
      api_secret: "s",
      ssl_verify: false
    }

    status = C.fetch_status(client)

    assert status["cpu"] == %{"total_pct" => 42.0}
    assert status["memory"]["total_mb"] == 2000.0
    assert status["memory"]["used_pct"] == 25.0
    assert [%{"mountpoint" => "/", "used_pct" => 61.0}] = status["disks"]

    # And it feeds the checks engine (the whole point of shape parity).
    keys = %{"status" => status} |> Orbit.Checks.Evaluate.evaluate() |> Enum.map(& &1.key)
    assert "cpu" in keys and "memory" in keys and "disk:/" in keys
  end

  describe "interfaces (client.py interface_statistics port)" do
    test "deduplicates on the short BSD name and keeps the zone in the label" do
      stats = %{
        "statistics" => %{
          "[LAN] (vmx0) / 00:50:56:be:dd:5b" => %{
            "name" => "vmx0",
            "flags" => "0x8843",
            "address" => "10.20.1.1",
            "received-bytes" => 1234,
            "sent-bytes" => 5678
          },
          # same interface, second address — must not produce a second row
          "[LAN] (vmx0) / fe80::250:56ff" => %{"name" => "vmx0", "flags" => "0x8843"},
          "[WAN] (vmx1) / 00:50:56:be:dd:5c" => %{"name" => "vmx1", "flags" => "0x8802"}
        }
      }

      ifaces = C.interfaces_from_statistics(stats)

      assert length(ifaces) == 2
      lan = Enum.find(ifaces, &(&1["name"] == "[LAN] vmx0"))
      assert lan["status"] == "up"
      assert lan["address"] == "10.20.1.1"
      # Byte-counter keys match the agent push shape, so the iface.* series
      # stays continuous when a box switches transport.
      assert lan["bytes_received"] == 1234
      assert lan["bytes_transmitted"] == 5678

      assert Enum.find(ifaces, &(&1["name"] == "[WAN] vmx1"))["status"] == "down"
    end

    test "accepts the bare statistics map and survives junk" do
      assert C.interfaces_from_statistics(%{"em0" => %{"name" => "em0"}}) != []
      assert C.interfaces_from_statistics(nil) == []
      assert C.interfaces_from_statistics([]) == []
    end

    test "FreeBSD hex flags decode to a readable status" do
      # 0x8843 = UP|BROADCAST|RUNNING|… ; 0x8802 has RUNNING but not UP
      assert C.iface_status("0x8843") == "up"
      assert C.iface_status("0x8801") == "up (not running)"
      assert C.iface_status("0x8802") == "down"
      assert C.iface_status("up") == "up"
      assert C.iface_status("") == "unknown"
      assert C.iface_status(nil) == "unknown"
    end
  end

  describe "uptime + system sections" do
    test "parses the activity header, days and clock-only forms" do
      header = "last pid: 80943;  load averages:  0.45,  0.33  up 1+18:18:17    10:16:21"
      assert C.uptime_from_activity(%{"headers" => [header]}) == "1d 18h 18m"

      assert C.uptime_from_activity(%{"headers" => ["… up 18:18:17  10:16:21"]}) == "18h 18m"
    end

    test "no header yields nil, never a fake zero uptime" do
      # A 0 here would fake a reboot into the system.uptime_seconds sawtooth.
      assert C.uptime_from_activity(%{"headers" => ["nothing useful"]}) == nil
      assert C.uptime_from_activity(%{}) == nil
      assert C.uptime_from_activity(nil) == nil
    end

    test "uptime feeds the metrics parser" do
      uptime = C.uptime_from_activity(%{"headers" => ["… up 1+02:03:04"]})
      assert Orbit.Metrics.uptime_to_seconds(uptime) == 86_400 + 2 * 3600 + 3 * 60
    end

    test "system section carries hostname and running version" do
      assert C.system_from_information(%{"name" => "opn1", "versions" => ["OPNsense 24.7.1"]}) ==
               %{"hostname" => "opn1", "os" => "OPNsense 24.7.1"}

      assert C.system_from_information(%{}) == nil
      assert C.system_from_information(nil) == nil
    end
  end

  test "a failing endpoint yields no section, never a crash" do
    Req.Test.stub(Orbit.Poller.OpnsenseClient, fn conn ->
      Plug.Conn.send_resp(conn, 500, "boom")
    end)

    client = %C{
      base_url: "https://box.example:4444",
      api_key: "k",
      api_secret: "s",
      ssl_verify: false
    }

    assert C.fetch_status(client) == %{}
  end
end
