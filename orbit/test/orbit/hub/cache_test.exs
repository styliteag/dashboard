defmodule Orbit.Hub.CacheTest do
  @moduledoc """
  Guard semantics mirrored from hub.py `_handle_metrics` — the incident
  class these prevent: one failed collector erased known-good state and
  fired alert pairs (CLAUDE.md named mistake 18).
  """

  use ExUnit.Case, async: true

  alias Orbit.Hub.Cache

  @now ~U[2026-07-17 12:00:00Z]

  defp seeded do
    Cache.ingest(
      %{},
      7,
      %{
        "ts" => "2026-07-17T11:59:30+00:00",
        "cpu" => %{"total" => 12.5},
        "gateways" => [%{"name" => "WAN_GW", "status" => "online"}],
        "ipsec" => [%{"name" => "to-opn1", "state" => "up"}],
        "services" => [%{"name" => "unbound", "running" => true}],
        "certificates" => [%{"cn" => "box.example"}],
        "firmware" => %{"current" => "2.8.1"},
        "pf_top" => %{"states" => 123},
        "connectivity" => [%{"id" => 1, "ok" => true}],
        "firewall_log" => [%{"line" => 1}],
        "external_ip" => %{"ipv4" => "203.0.113.7", "ipv6" => ""}
      },
      @now
    )
  end

  describe "truthy-guarded sections (empty = collector failure, keep cache)" do
    test "empty list does not wipe gateways/ipsec/services/certificates" do
      cache = seeded()

      wiped =
        Cache.ingest(
          cache,
          7,
          %{
            "gateways" => [],
            "ipsec" => [],
            "services" => [],
            "certificates" => [],
            "firmware" => %{},
            "pf_top" => nil
          },
          @now
        )

      entry = Cache.entry(wiped, 7)
      assert entry["gateways"] == [%{"name" => "WAN_GW", "status" => "online"}]
      assert entry["ipsec"] == [%{"name" => "to-opn1", "state" => "up"}]
      assert entry["services"] == [%{"name" => "unbound", "running" => true}]
      assert entry["certificates"] == [%{"cn" => "box.example"}]
      assert entry["firmware"] == %{"current" => "2.8.1"}
      assert entry["pf_top"] == %{"states" => 123}
    end

    test "non-empty sections overwrite" do
      cache = seeded()
      updated = Cache.ingest(cache, 7, %{"gateways" => [%{"name" => "NEW"}]}, @now)
      assert Cache.entry(updated, 7)["gateways"] == [%{"name" => "NEW"}]
    end
  end

  describe "presence-guarded sections (empty is legitimate)" do
    test "empty connectivity list DOES overwrite (no monitors configured)" do
      cache = seeded()
      updated = Cache.ingest(cache, 7, %{"connectivity" => []}, @now)
      assert Cache.entry(updated, 7)["connectivity"] == []
    end

    test "absent connectivity key keeps the cache" do
      cache = seeded()
      updated = Cache.ingest(cache, 7, %{"cpu" => %{}}, @now)
      assert Cache.entry(updated, 7)["connectivity"] == [%{"id" => 1, "ok" => true}]
    end

    test "empty firewall_log overwrites likewise" do
      cache = seeded()
      updated = Cache.ingest(cache, 7, %{"firewall_log" => []}, @now)
      assert Cache.entry(updated, 7)["firewall_log"] == []
    end
  end

  describe "external_ip any-address-present guard" do
    test "all-empty section keeps the last known IP (both probes failed)" do
      cache = seeded()
      updated = Cache.ingest(cache, 7, %{"external_ip" => %{"ipv4" => "", "ipv6" => ""}}, @now)
      assert Cache.entry(updated, 7)["external_ip"]["ipv4"] == "203.0.113.7"
    end

    test "a new address overwrites" do
      cache = seeded()
      updated = Cache.ingest(cache, 7, %{"external_ip" => %{"ipv4" => "198.51.100.9"}}, @now)
      assert Cache.entry(updated, 7)["external_ip"]["ipv4"] == "198.51.100.9"
    end
  end

  test "status sections always overwrite and last_metrics_ts advances" do
    cache = seeded()
    later = DateTime.add(@now, 30, :second)
    updated = Cache.ingest(cache, 7, %{"cpu" => %{"total" => 99.0}}, later)
    entry = Cache.entry(updated, 7)
    assert entry["status"]["cpu"] == %{"total" => 99.0}
    assert entry["last_metrics_ts"] == later
  end

  describe "interface throughput" do
    defp push(bytes) do
      %{
        "interfaces" => [
          %{"name" => "em0", "bytes_received" => bytes, "bytes_transmitted" => bytes * 2}
        ]
      }
    end

    defp em0(cache), do: cache |> Cache.entry(7) |> get_in(["status", "interfaces"]) |> hd()

    test "a rate needs two pushes; the first one reports none" do
      cache = Cache.ingest(%{}, 7, push(1_000), @now)
      refute Map.has_key?(em0(cache), "rx_rate")

      # 10_000 - 1_000 bytes over 30 s = 300 B/s; tx doubles.
      cache = Cache.ingest(cache, 7, push(10_000), DateTime.add(@now, 30, :second))
      assert em0(cache)["rx_rate"] == 300.0
      assert em0(cache)["tx_rate"] == 600.0
    end

    test "a counter that went backwards yields no rate rather than a spike" do
      cache = Cache.ingest(%{}, 7, push(10_000), @now)
      # Box rebooted: the counters restart near zero. A naive diff would be a
      # large negative number, and abs() of it a fictional gigabit burst.
      cache = Cache.ingest(cache, 7, push(50), DateTime.add(@now, 30, :second))
      refute Map.has_key?(em0(cache), "rx_rate")
    end

    test "an interface the previous push did not carry gets no rate" do
      cache = Cache.ingest(%{}, 7, push(1_000), @now)

      data = %{"interfaces" => [%{"name" => "em9", "bytes_received" => 5_000}]}
      cache = Cache.ingest(cache, 7, data, DateTime.add(@now, 30, :second))

      refute Map.has_key?(em0(cache), "rx_rate")
    end

    test "a gap longer than the window reports nothing rather than an average" do
      # The cache is rehydrated from a snapshot at boot, so `prev` can be
      # hours old. Diffing across the outage would label the whole downtime's
      # average as current throughput.
      cache = Cache.ingest(%{}, 7, push(1_000), @now)
      cache = Cache.ingest(cache, 7, push(90_000_000), DateTime.add(@now, 4, :hour))
      refute Map.has_key?(em0(cache), "rx_rate")
    end

    test "two pushes inside the same second do not divide by zero" do
      cache = Cache.ingest(%{}, 7, push(1_000), @now)
      cache = Cache.ingest(cache, 7, push(2_000), @now)
      refute Map.has_key?(em0(cache), "rx_rate")
    end
  end

  test "instances are isolated; drop removes one" do
    cache = seeded()
    cache = Cache.ingest(cache, 8, %{"gateways" => [%{"name" => "OTHER"}]}, @now)
    assert Cache.entry(cache, 7)["gateways"] != Cache.entry(cache, 8)["gateways"]
    assert Cache.entry(Cache.drop(cache, 7), 7) == %{}
  end

  describe "x_* vendor passthrough (agent drop-in backend hook, §28)" do
    test "an x_ section is stored verbatim; a non-x_ unknown section is dropped" do
      cache =
        Cache.ingest(
          %{},
          7,
          %{"x_zfs" => %{"arc" => %{"hit_ratio_pct" => 82.2}}, "bogus" => %{"a" => 1}},
          @now
        )

      assert Cache.entry(cache, 7)["x_zfs"] == %{"arc" => %{"hit_ratio_pct" => 82.2}}
      refute Map.has_key?(Cache.entry(cache, 7), "bogus")
    end

    test "an empty x_ push does not wipe a known-good vendor section" do
      cache = Cache.ingest(%{}, 7, %{"x_zfs" => %{"arc" => %{"size" => 1}}}, @now)
      kept = Cache.ingest(cache, 7, %{"x_zfs" => %{}}, @now)
      assert kept |> Cache.entry(7) |> Map.fetch!("x_zfs") == %{"arc" => %{"size" => 1}}
    end
  end

  describe "checkmk_output retention (raw agent dump for the Checkmk view)" do
    test "a pushed checkmk_output is retained; an empty push does not wipe it" do
      cache = Cache.ingest(%{}, 7, %{"checkmk_output" => "<<<mem>>>\nMemTotal: 1"}, @now)
      assert Cache.entry(cache, 7)["checkmk_output"] =~ "MemTotal"

      # A later push without checkmk_raw (no checkmk_output) keeps the last dump.
      kept = Cache.ingest(cache, 7, %{"cpu" => %{"total" => 5}}, @now)
      assert Cache.entry(kept, 7)["checkmk_output"] =~ "MemTotal"
    end
  end
end
