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

  test "instances are isolated; drop removes one" do
    cache = seeded()
    cache = Cache.ingest(cache, 8, %{"gateways" => [%{"name" => "OTHER"}]}, @now)
    assert Cache.entry(cache, 7)["gateways"] != Cache.entry(cache, 8)["gateways"]
    assert Cache.entry(Cache.drop(cache, 7), 7) == %{}
  end
end
