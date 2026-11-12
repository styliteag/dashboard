defmodule Orbit.Checks.CheckSourceTest do
  @moduledoc """
  Every core check names the cache section it is evaluated from
  (`ServiceCheck.source`), and the cache records which sections the last
  Checkmk run produced (`checkmk_sections`). Together a downstream build can
  tell a check derived from a Linux node's Checkmk output (which a Checkmk
  server evaluates itself) from one only the dashboard has.
  """

  use ExUnit.Case, async: true

  alias Orbit.Checks.Evaluate
  alias Orbit.Hub.Cache

  @fixture Path.join([__DIR__, "..", "..", "support", "fixtures", "checkmk_linux.b64"])
           |> Path.expand()
           |> File.read!()
           |> String.trim()

  test "core checks carry their source section" do
    checks =
      Evaluate.evaluate(%{
        "status" => %{
          "memory" => %{
            "used_pct" => 50.0,
            "total_mb" => 1000,
            "swap_total_mb" => 100,
            "swap_used_pct" => 1.0
          },
          "cpu" => %{"total_pct" => 10.0},
          "disks" => [%{"mountpoint" => "/", "used_pct" => 40.0, "total_gb" => 10}]
        },
        "gateways" => [%{"name" => "WAN_GW", "status" => "online"}],
        "services" => [%{"name" => "unbound", "running" => true}]
      })

    sources = Map.new(checks, &{&1.key, &1.source})

    assert sources["memory"] == "memory"
    assert sources["swap"] == "memory"
    assert sources["cpu"] == "cpu"
    assert Enum.any?(checks, &(&1.source == "disks"))
    assert Enum.any?(checks, &(&1.source == "gateways"))
    assert Enum.any?(checks, &(&1.source == "services"))
  end

  test "the cache records every section a Checkmk run produced" do
    raw = %{"output_gz_b64" => @fixture, "interval" => 60}
    now = ~U[2026-11-12 12:00:00Z]
    {data, cpu} = Cache.expand(%{}, 7, %{"checkmk_raw" => raw}, now)
    entry = %{} |> Cache.ingest(7, data, now, cpu) |> Cache.entry(7)

    assert "memory" in entry["checkmk_sections"]
    assert "disks" in entry["checkmk_sections"]
    refute "gateways" in entry["checkmk_sections"]

    # a push between runs keeps the last run's list
    {later, _} = Cache.expand(%{7 => entry}, 7, %{"checkmk_raw" => %{}}, DateTime.add(now, 30))
    kept = %{7 => entry} |> Cache.ingest(7, later, DateTime.add(now, 30)) |> Cache.entry(7)
    assert kept["checkmk_sections"] == entry["checkmk_sections"]
  end
end
