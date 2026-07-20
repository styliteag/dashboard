defmodule Orbit.ExternalIpTest do
  @moduledoc """
  Public-IP view across every transport (ExternalIpSection parity, widened
  past the agent). The point of the module is that a poll-mode box answers
  the same question as an agent box, so every test names its transport.
  """

  use ExUnit.Case, async: true

  alias Orbit.ExternalIp

  # -- agent push: the ipify probe wins ---------------------------------------

  test "agent probe is the source and beats the interface addresses" do
    entry = %{
      "external_ip" => %{
        "ipv4" => "84.180.138.206",
        "ipv6" => "2003:c2:17ff:b4c::1",
        "checked_at" => "2026-07-20T08:34:00+00:00"
      },
      "status" => %{"interfaces" => [%{"address" => "10.20.1.198"}]}
    }

    view = ExternalIp.build(entry, source_ip: "203.0.113.9", connected: true)

    assert view.ipv4 == "84.180.138.206"
    assert view.ipv6 == "2003:c2:17ff:b4c::1"
    assert view.source == :probe
    assert view.source_ip == "203.0.113.9"
    assert view.connected
    assert view.checked_at == "2026-07-20T08:34:00+00:00"
  end

  test "public IPv4 not on any interface ⇒ behind NAT" do
    entry = %{
      "external_ip" => %{"ipv4" => "84.180.138.206"},
      "status" => %{"interfaces" => [%{"address" => "10.20.1.198"}]}
    }

    assert ExternalIp.build(entry).nat == :behind_nat
  end

  test "public IPv4 configured on an interface ⇒ direct" do
    entry = %{
      "external_ip" => %{"ipv4" => "203.0.113.7"},
      "status" => %{"interfaces" => [%{"address" => "10.0.0.1"}, %{"address" => "203.0.113.7"}]}
    }

    assert ExternalIp.build(entry).nat == :direct
  end

  # -- poll transports: the interface address IS the public address -----------

  test "securepoint: a routable WAN address is the external IP, CIDR and all" do
    # Securepoint reports addresses with a prefix ("213.232.100.192/32") —
    # comparing them raw made a perfectly public WAN address parse as nothing
    # (live payload from the bensheim box, 2026-07-20).
    entry = %{
      "status" => %{
        "interfaces" => [
          %{"name" => "A1", "address" => "10.21.0.1/22"},
          %{"name" => "wan0", "address" => "213.232.100.192/32"},
          %{"name" => "wlan0", "address" => "10.21.16.1/24"}
        ]
      }
    }

    view = ExternalIp.build(entry)

    assert view.ipv4 == "213.232.100.192"
    assert view.source == :interface
    # It is configured on the box's own interface — no upstream NAT.
    assert view.nat == :direct
    # A poll-mode box never connects to us.
    assert view.source_ip == nil
    refute view.connected
  end

  test "opnsense poll: the per-interface address list is considered" do
    # The OPNsense poller carries every configured address of an interface in
    # "addresses" (it reports an interface once per address).
    entry = %{
      "status" => %{
        "interfaces" => [
          %{
            "name" => "vtnet1",
            "address" => "198.51.100.10",
            "addresses" => ["198.51.100.10", "fe80::1"]
          }
        ]
      }
    }

    view = ExternalIp.build(entry)

    assert view.ipv4 == "198.51.100.10"
    assert view.nat == :direct
  end

  test "only private addresses ⇒ nothing claimed, NAT unknown" do
    entry = %{"status" => %{"interfaces" => [%{"address" => "192.168.1.1"}]}}
    view = ExternalIp.build(entry)

    assert view.ipv4 == nil
    assert view.ipv6 == nil
    assert view.source == nil
    # Never guess: without a public IPv4 there is no NAT verdict to give.
    assert view.nat == :unknown
    refute ExternalIp.known?(view)
  end

  test "no interfaces at all ⇒ NAT unknown even with a probed address" do
    entry = %{"external_ip" => %{"ipv4" => "84.180.138.206"}, "status" => %{}}
    view = ExternalIp.build(entry)

    assert view.ipv4 == "84.180.138.206"
    # Nothing to cross-check against — "behind NAT" would be a coin flip.
    assert view.nat == :unknown
    assert ExternalIp.known?(view)
  end

  test "known?/1 is true as soon as the hub saw the box connect" do
    view = ExternalIp.build(%{"status" => %{}}, source_ip: "203.0.113.9", connected: true)
    assert ExternalIp.known?(view)
  end

  test "blank probe strings are treated as absent, not as an address" do
    entry = %{"external_ip" => %{"ipv4" => "", "ipv6" => "   "}, "status" => %{}}
    view = ExternalIp.build(entry)

    assert view.ipv4 == nil
    assert view.ipv6 == nil
    refute ExternalIp.known?(view)
  end

  test "IPv6 zone suffixes are stripped before comparing" do
    entry = %{
      "external_ip" => %{"ipv6" => "2003:c2::1"},
      "status" => %{"interfaces" => [%{"address" => "fe80::be24:20ff:fead:1994%vtnet0"}]}
    }

    assert "fe80::be24:20ff:fead:1994" in ExternalIp.interface_addresses(entry)
  end
end
