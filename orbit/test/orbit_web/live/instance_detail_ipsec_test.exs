defmodule OrbitWeb.InstanceDetailIpsecTest do
  @moduledoc """
  The raw `ipsec` hub section arrives in two shapes and the detail page must
  survive both.

  Regression: `load_metrics/1` hardcoded the agent/OPNsense map shape as
  `(entry["ipsec"] || %{})["tunnels"]`. A Securepoint box stores the section as
  a BARE LIST (every Orbit.Securepoint.Client section is a list), so Access
  raised `ArgumentError: the Access module supports only keyword lists (with
  atom keys), got: "tunnels"` and GET /instances/:id answered 500 for every
  Securepoint instance. On the pre-fix tree the list case below raises.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.InstanceDetailLive, as: L

  test "agent/OPNsense map shape yields tunnels and the running flag" do
    section = %{"running" => true, "tunnels" => [%{"name" => "t1"}, %{"name" => "t2"}]}

    assert {[%{"name" => "t1"}, %{"name" => "t2"}], true} = L.normalize_ipsec(section)
  end

  test "securepoint bare list yields the tunnels and no running flag" do
    section = [%{"name" => "utm-tunnel"}]

    assert {[%{"name" => "utm-tunnel"}], nil} = L.normalize_ipsec(section)
  end

  test "empty securepoint list is not mistaken for a map" do
    assert {[], nil} = L.normalize_ipsec([])
  end

  test "map without a tunnels key keeps the running flag" do
    assert {[], false} = L.normalize_ipsec(%{"running" => false})
  end

  test "missing section" do
    assert {[], nil} = L.normalize_ipsec(nil)
  end

  test "a junk value degrades instead of crashing the page" do
    assert {[], nil} = L.normalize_ipsec("unexpected")
  end
end
