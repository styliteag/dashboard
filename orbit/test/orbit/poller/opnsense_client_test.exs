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
