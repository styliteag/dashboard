defmodule Orbit.Ipsec.LocalEndpointTest do
  @moduledoc """
  lip-mismatch: a tunnel pinning a public local endpoint the box no longer
  owns (2.9.10 parity). Informational — the rule must never fire on a shape
  that is merely normal.
  """

  use ExUnit.Case, async: true

  alias Orbit.Ipsec.LocalEndpoint

  @box %{ipv4: "203.0.113.7"}

  test "a public local endpoint that differs from the box's public IP is drift" do
    # The box moved behind NAT, or its WAN address changed: phase 1 then
    # fails without the tunnel status ever saying why.
    assert LocalEndpoint.mismatch?("198.51.100.9", @box)
  end

  test "the box's own public address is not drift" do
    refute LocalEndpoint.mismatch?("203.0.113.7", @box)
  end

  test "a private local endpoint is the normal shape behind NAT, never flagged" do
    # Flagging this would put the badge on every tunnel of every NATed box.
    refute LocalEndpoint.mismatch?("10.21.7.100", @box)
    refute LocalEndpoint.mismatch?("192.168.1.1", @box)
    refute LocalEndpoint.mismatch?("172.16.0.1", @box)
  end

  test "nothing is claimed without both addresses" do
    refute LocalEndpoint.mismatch?(nil, @box)
    refute LocalEndpoint.mismatch?("", @box)
    refute LocalEndpoint.mismatch?("%any", @box)
    # No known public address for the box ⇒ no verdict.
    refute LocalEndpoint.mismatch?("198.51.100.9", %{ipv4: nil})
    refute LocalEndpoint.mismatch?("198.51.100.9", %{})
  end

  test "a CIDR or zone suffix on the endpoint does not defeat the comparison" do
    refute LocalEndpoint.mismatch?("203.0.113.7/32", @box)
    assert LocalEndpoint.mismatch?("198.51.100.9/32", @box)
  end

  test "the hint names both addresses" do
    hint = LocalEndpoint.hint("198.51.100.9", @box)
    assert hint =~ "198.51.100.9"
    assert hint =~ "203.0.113.7"
  end
end
