defmodule Orbit.Ipsec.LocalEndpointTest do
  @moduledoc """
  lip-mismatch: a DOWN tunnel pinning a public local endpoint the box no
  longer owns (2.9.10 parity). Informational — the rule must never fire on a
  shape that is merely normal, and never on a tunnel that is up.
  """

  use ExUnit.Case, async: true

  alias Orbit.Ipsec.LocalEndpoint

  @box %{ipv4: "203.0.113.7"}
  # A tunnel that is trying and failing to come up — the only shape the hint
  # is about ("CONNECTING forever").
  @down "connecting"

  test "a public local endpoint that differs from the box's public IP is drift" do
    # The box moved behind NAT, or its WAN address changed: phase 1 then
    # fails without the tunnel status ever saying why.
    assert LocalEndpoint.mismatch?("198.51.100.9", @down, @box)
  end

  test "an established tunnel is never drift, whatever its local endpoint" do
    # Regression: a Securepoint carrying several public IPs showed drift on
    # tunnels that were plainly ESTABLISHED but bound to a public address
    # other than the box's first interface address. You cannot hold a live
    # IKE SA from an address you do not own, so up ⇒ no drift, period.
    for status <- ["ESTABLISHED", "established", "installed", "connected", "up"] do
      refute LocalEndpoint.mismatch?("198.51.100.9", status, @box)
    end
  end

  test "a public endpoint the box owns on a second interface is not drift" do
    # The box's derived public IP is only the FIRST routable interface
    # address; a box with a WAN block owns more. Matching only the first one
    # false-flagged every tunnel bound to a sibling public address.
    box = %{ipv4: "203.0.113.7", interface_addresses: ["10.0.0.1", "198.51.100.9"]}
    refute LocalEndpoint.mismatch?("198.51.100.9", @down, box)
    # A public address on none of the box's interfaces is still drift.
    assert LocalEndpoint.mismatch?("192.0.2.50", @down, box)
  end

  test "the box's own public address is not drift" do
    refute LocalEndpoint.mismatch?("203.0.113.7", @down, @box)
  end

  test "a private local endpoint is the normal shape behind NAT, never flagged" do
    # Flagging this would put the badge on every tunnel of every NATed box.
    refute LocalEndpoint.mismatch?("10.21.7.100", @down, @box)
    refute LocalEndpoint.mismatch?("192.168.1.1", @down, @box)
    refute LocalEndpoint.mismatch?("172.16.0.1", @down, @box)
  end

  test "nothing is claimed without both addresses" do
    refute LocalEndpoint.mismatch?(nil, @down, @box)
    refute LocalEndpoint.mismatch?("", @down, @box)
    refute LocalEndpoint.mismatch?("%any", @down, @box)
    # No known public address for the box ⇒ no verdict.
    refute LocalEndpoint.mismatch?("198.51.100.9", @down, %{ipv4: nil})
    refute LocalEndpoint.mismatch?("198.51.100.9", @down, %{})
  end

  test "a CIDR or zone suffix on the endpoint does not defeat the comparison" do
    refute LocalEndpoint.mismatch?("203.0.113.7/32", @down, @box)
    assert LocalEndpoint.mismatch?("198.51.100.9/32", @down, @box)
  end

  test "the hint names both addresses" do
    hint = LocalEndpoint.hint("198.51.100.9", @box)
    assert hint =~ "198.51.100.9"
    assert hint =~ "203.0.113.7"
  end
end
