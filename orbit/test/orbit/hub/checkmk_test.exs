defmodule Orbit.Hub.CheckmkTest do
  @moduledoc """
  Linux-node section import. The fixture is real `check_mk_agent` output
  captured from the lab box ubn1 (Ubuntu 26.04, agent 2.5.0p8) on
  2026-07-20, trimmed to the sections the parser reads.
  """

  use ExUnit.Case, async: true

  alias Orbit.Hub.Checkmk

  @fixture Path.join([__DIR__, "..", "..", "support", "fixtures", "checkmk_linux.b64"])
           |> Path.expand()
           |> File.read!()
           |> String.trim()

  defp payload, do: %{"output_gz_b64" => @fixture}

  test "memory comes out as the shape the checks engine already knows" do
    {sections, _cpu} = Checkmk.parse(payload())
    mem = sections["memory"]

    assert mem["total_mb"] == 1895
    # MemAvailable (not MemFree) drives used_pct — cache is not "used".
    assert mem["used_pct"] < 30.0
    # ubn1 has a swap file; the swap check keys must be populated so
    # swap_check/1 can fire (it returns nil on swap_total_mb <= 0).
    assert mem["swap_total_mb"] > 0
    assert is_float(mem["swap_used_pct"])
  end

  test "cpu needs two samples: first push yields no percentage, second does" do
    {first, state} = Checkmk.parse(payload())

    # /proc/stat is cumulative — a single sample cannot express utilisation,
    # and inventing 0% is what made a busy Linux box look idle.
    refute Map.has_key?(first, "cpu")
    assert %{"busy" => busy, "total" => total} = state
    assert busy > 0 and total > busy

    later = %{"busy" => busy - 50, "total" => total - 200}
    {second, _} = Checkmk.parse(payload(), later)
    # 50 busy jiffies out of 200 elapsed = 25%.
    assert second["cpu"]["total_pct"] == 25.0
  end

  test "a counter reset (reboot) reports nothing rather than a bogus spike" do
    {_, state} = Checkmk.parse(payload())
    after_reboot = %{"busy" => state["busy"] + 10_000, "total" => state["total"] + 10_000}

    {sections, _} = Checkmk.parse(payload(), after_reboot)
    refute Map.has_key?(sections, "cpu")
  end

  test "disks skip the inode and lsblk blocks and keep one row per mountpoint" do
    {sections, _} = Checkmk.parse(payload())
    disks = sections["disks"]

    root = Enum.find(disks, &(&1["mountpoint"] == "/"))
    assert root["used_pct"] == 65.0
    assert root["device"] == "/dev/sda2"
    assert root["total_mb"] > 7000

    # df_v2 emits the same mountpoints again inside [df_inodes_start] — those
    # rows are counts, not sizes, and must not become a second disk.
    assert length(disks) == length(Enum.uniq_by(disks, & &1["mountpoint"]))
    refute Enum.any?(disks, &(&1["mountpoint"] in ["[df_inodes_start]", "NAME"]))
  end

  test "interfaces carry byte counters under the same keys as the agent push" do
    {sections, _} = Checkmk.parse(payload())
    eth = Enum.find(sections["interfaces"], &(&1["name"] == "eth0"))

    assert eth["bytes_received"] > 0
    assert eth["bytes_transmitted"] > 0
    assert eth["status"] == "up"
  end

  test "loadavg carries the core count so the load check can normalise" do
    {sections, _} = Checkmk.parse(payload())
    load = sections["loadavg"]

    assert load["cores"] == 2
    assert is_float(load["five"])
  end

  test "uptime is the human string the firewall agents push, not a map" do
    {sections, _} = Checkmk.parse(payload())

    # The detail page renders this value straight into HEEx — a map crashed
    # the whole Overview tab with a Phoenix.HTML.Safe protocol error.
    assert is_binary(sections["uptime"])
    assert sections["uptime"] =~ ~r/^\d+ days?, \d+:\d{2}$|^\d+:\d{2}$/
  end

  test "the parsed sections actually produce checks" do
    {_first, state} = Checkmk.parse(payload())

    {sections, _} =
      Checkmk.parse(payload(), %{"busy" => state["busy"] - 5, "total" => state["total"] - 100})

    keys = %{"status" => sections} |> Orbit.Checks.Evaluate.evaluate() |> Enum.map(& &1.key)

    assert "cpu" in keys
    assert "memory" in keys
    assert "load" in keys
    assert "disk:/" in keys
  end

  test "chrony maps onto the same ntp shape the FreeBSD boxes report" do
    {sections, _} = Checkmk.parse(payload())
    ntp = sections["ntp"]

    assert ntp["synced"] == true
    assert ntp["stratum"] == 3
    assert is_float(ntp["offset_ms"])

    # The unchanged FreeBSD check must accept it.
    assert %{key: "ntp", state: 0} = Orbit.Checks.Evaluate.ntp_check(ntp)
  end

  test "only failed systemd units become services" do
    {sections, _} = Checkmk.parse(payload())
    services = sections["services"] || []

    # ubn1 is healthy: no failed unit, so no service rows — reporting all 400
    # units would drown the services view and emit hundreds of checks.
    assert Enum.all?(services, &(&1["running"] == false))
  end

  test "a failed unit is reported and drives a service check" do
    text = """
    <<<systemd_units>>>
    [status]
    ● nginx.service - A high performance web server
     Active: failed (Result: exit-code) since Mon 2026-07-20 09:00:00 CEST
    ● ssh.service - OpenBSD Secure Shell server
     Active: active (running) since Sat 2026-07-11 22:22:37 CEST
    """

    b64 = text |> :zlib.gzip() |> Base.encode64()
    {sections, _} = Checkmk.parse(%{"output_gz_b64" => b64})

    assert [%{"name" => "nginx.service", "running" => false}] = sections["services"]
  end

  test "garbage in leaves the cached values alone instead of blanking the box" do
    assert {%{}, nil} = Checkmk.parse(%{"output_gz_b64" => "not base64!!"})
    assert {%{}, nil} = Checkmk.parse(%{"output_gz_b64" => Base.encode64("not gzip")})
    assert {%{}, nil} = Checkmk.parse(%{})
    assert {%{}, nil} = Checkmk.parse(nil)

    # A corrupt push must not wipe the CPU baseline either.
    prev = %{"busy" => 1, "total" => 2}
    assert {%{}, ^prev} = Checkmk.parse(%{"output_gz_b64" => "!!"}, prev)
  end

  test "sections Orbit has no home for are ignored, not guessed at" do
    text = "<<<systemd_units>>>\nfoo enabled\n<<<uptime>>>\n42.0 1.0\n"
    b64 = text |> :zlib.gzip() |> Base.encode64()

    {sections, _} = Checkmk.parse(%{"output_gz_b64" => b64})

    assert sections == %{"uptime" => "0:00"}
  end
end
