defmodule Orbit.GeoIP.RulesTest do
  @moduledoc """
  Pure decision-logic port tests mirroring test_geoip.py: the decide/6
  evaluation order is a security contract (whitelist > blocklist >
  country-allow, DR-G3 allow-all, DR-G5 fail-open/fail-closed split).
  """

  use ExUnit.Case, async: true

  alias Orbit.GeoIP.Rules

  @none MapSet.new()

  defp rules(attrs) do
    Rules.parse_rules(
      Keyword.get(attrs, :enabled, true),
      Jason.encode!(Keyword.get(attrs, :countries, [])),
      Jason.encode!(Keyword.get(attrs, :whitelist, []))
    )
  end

  describe "classify_entry/1" do
    test "CIDRs v4/v6 parse; single IPs normalize to /32 and /128" do
      assert {:cidr, {{10, 0, 0, 0}, 8}} = Rules.classify_entry("10.0.0.0/8")
      assert {:cidr, {_, 32}} = Rules.classify_entry("192.0.2.7")
      assert {:cidr, {_, 32}} = Rules.classify_entry("2001:db8::/32")
      assert {:cidr, {_, 128}} = Rules.classify_entry("2001:db8::1")
    end

    test "hostnames need a dot; garbage and bare labels are rejected" do
      assert {:hostname, "host.dyndns.de"} = Rules.classify_entry("Host.DynDNS.de")
      assert :error = Rules.classify_entry("bare-label")
      assert :error = Rules.classify_entry("")
      assert :error = Rules.classify_entry("10.0.0.0/33")
      assert :error = Rules.classify_entry("not a host!")
    end
  end

  describe "parse_rules/3" do
    test "tolerant: broken json and junk entries degrade, never crash" do
      parsed = Rules.parse_rules(true, "{not json", "[\"10.0.0.0/8\", \"???\", 42]")
      assert parsed.countries == MapSet.new()
      assert length(parsed.cidrs) == 1
      assert parsed.hostnames == []
    end

    test "countries are upcased, non-2-letter entries dropped" do
      parsed = Rules.parse_rules(true, ~s(["de", "AT", "DEU", 7]), "[]")
      assert parsed.countries == MapSet.new(["DE", "AT"])
    end
  end

  describe "restricting?/1" do
    test "DR-G3: disabled or empty config cannot block" do
      refute Rules.restricting?(Rules.disabled())
      refute Rules.restricting?(rules(enabled: false, countries: ["DE"]))
      refute Rules.restricting?(rules(countries: []))
      assert Rules.restricting?(rules(countries: ["DE"]))
      assert Rules.restricting?(rules(whitelist: ["10.0.0.0/8"]))
    end
  end

  describe "ip_whitelisted?/3" do
    test "CIDR matching is version-aware, v4 and v6" do
      r = rules(whitelist: ["10.0.0.0/8", "2001:db8::/32"])
      assert Rules.ip_whitelisted?("10.1.2.3", r, @none)
      refute Rules.ip_whitelisted?("11.1.2.3", r, @none)
      assert Rules.ip_whitelisted?("2001:db8:0:1::5", r, @none)
      refute Rules.ip_whitelisted?("2001:db9::1", r, @none)
      # A v4 address never matches a v6 net (and vice versa).
      refute Rules.ip_whitelisted?("10.0.0.1", rules(whitelist: ["2001:db8::/32"]), @none)
    end

    test "dyndns-resolved IPs and unparseable input" do
      r = rules(whitelist: ["host.dyndns.de"])
      assert Rules.ip_whitelisted?("203.0.113.9", r, MapSet.new(["203.0.113.9"]))
      refute Rules.ip_whitelisted?("203.0.113.9", r, @none)
      refute Rules.ip_whitelisted?("garbage", r, @none)
    end
  end

  describe "decide/6 — evaluation order contract" do
    test "not restricting and no blocklist: allow" do
      d = Rules.decide("1.2.3.4", Rules.disabled(), nil, @none, true)
      assert %{allowed: true, reason: "not_restricting"} = d
    end

    test "whitelist beats the blocklist (operator rescue first)" do
      r = rules(countries: ["DE"], whitelist: ["10.0.0.0/8"])
      banned = fn _ip -> true end
      d = Rules.decide("10.1.1.1", r, "RU", @none, true, banned)
      assert %{allowed: true, reason: "whitelisted"} = d
    end

    test "blocklist bites even with the country restriction off (DR-G8)" do
      banned = fn ip -> ip == "6.6.6.6" end
      d = Rules.decide("6.6.6.6", Rules.disabled(), nil, @none, true, banned)
      assert %{allowed: false, reason: "crowdsec_banned"} = d

      d2 = Rules.decide("7.7.7.7", Rules.disabled(), nil, @none, true, banned)
      assert %{allowed: true, reason: "not_restricting"} = d2
    end

    test "restricting + mmdb unavailable fails OPEN (DR-G5 infra failure)" do
      d = Rules.decide("1.2.3.4", rules(countries: ["DE"]), nil, @none, false)
      assert %{allowed: true, reason: "db_unavailable"} = d
    end

    test "country allowlist: allowed, blocked, and unknown fails CLOSED" do
      r = rules(countries: ["DE", "AT"])

      assert %{allowed: true, reason: "country_allowed"} =
               Rules.decide("1.1.1.1", r, "de", @none, true)

      assert %{allowed: false, reason: "country_blocked"} =
               Rules.decide("1.1.1.1", r, "RU", @none, true)

      # Private/unmapped IP with countries configured: deny (documented pitfall).
      assert %{allowed: false, reason: "no_country"} =
               Rules.decide("10.0.0.1", r, nil, @none, true)
    end

    test "whitelist-only config restricts nothing beyond its bypass role" do
      # Countries empty, whitelist set: restricting?=true, but a non-listed
      # IP with a country still hits the country branch — no countries
      # configured means nothing matches, so it denies. This mirrors the
      # python semantics exactly (whitelist entries imply enforcement).
      r = rules(whitelist: ["10.0.0.0/8"])

      assert %{allowed: true, reason: "whitelisted"} =
               Rules.decide("10.0.0.1", r, nil, @none, true)

      assert %{allowed: false, reason: "country_blocked"} =
               Rules.decide("1.1.1.1", r, "DE", @none, true)
    end
  end
end
