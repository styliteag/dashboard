defmodule Orbit.PushCardinalityTest do
  @moduledoc """
  Agent pushes are bounded before they fan out into DB rows: at most 32
  logfile snapshots per push, at most 64 disks and 128 interfaces turned into
  metric series (a push with thousands of made-up names must not mint
  thousands of series), and malformed entries are skipped, not crashed on.
  """
  use ExUnit.Case, async: true

  test "logfiles: entry count capped, non-map entries skipped" do
    raw = for(i <- 1..100, do: %{"name" => "f#{i}", "content" => "x"}) ++ ["junk", 42]
    assert length(Orbit.Logs.Store.sanitize(raw)) == 32
  end

  test "metrics: disk and interface series capped" do
    data = %{
      "disks" => for(i <- 1..500, do: %{"mountpoint" => "/m#{i}", "used_pct" => 1}),
      "interfaces" =>
        for(i <- 1..500, do: %{"name" => "if#{i}", "bytes_received" => 1}) ++ ["junk"]
    }

    names = data |> Orbit.Metrics.rows_for_push() |> Enum.map(&elem(&1, 0))
    assert Enum.count(names, &String.starts_with?(&1, "disk.")) == 64
    assert Enum.count(names, &String.starts_with?(&1, "iface.")) == 128 * 2
  end
end
