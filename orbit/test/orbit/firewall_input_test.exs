defmodule Orbit.FirewallInputTest do
  @moduledoc """
  Rule ids and the interface filter come from DOM attributes and end up in
  the OPNsense API path / query string (relayed by the agent as root). Only
  plain id tokens reach the path; the interface is form-encoded; rule field
  values are strings of bounded length without control characters.
  """
  use ExUnit.Case, async: true

  alias Orbit.Firewall

  defp inst, do: %Orbit.Instances.Instance{id: 7, name: "opn1", device_type: "opnsense"}
  defp no_relay, do: fn _m, path, _b -> flunk("relayed #{path}") end
  defp audit, do: fn _ -> :ok end

  @bad_ids [
    "../../core/firmware/update",
    "u1/../x",
    "a?b=1",
    "a#b",
    "a%2fb",
    "",
    nil,
    %{},
    String.duplicate("a", 65)
  ]

  test "path-unsafe rule ids are refused before any relay" do
    for id <- @bad_ids do
      o = [relay: no_relay(), audit: audit()]
      assert {:error, _} = Firewall.toggle_rule(inst(), id, true, o), inspect(id)
      assert {:error, _} = Firewall.delete_rule(inst(), id, o)
      assert {:error, _} = Firewall.get_rule(inst(), id, o)
      assert {:error, _} = Firewall.move_rule(inst(), id, "u2", o)
      assert {:error, _} = Firewall.move_rule(inst(), "u2", id, o)
    end

    for id <- @bad_ids -- [nil],
        do:
          assert(
            {:error, _} = Firewall.save_rule(inst(), id, %{}, relay: no_relay(), audit: audit())
          )
  end

  test "a real OPNsense uuid passes" do
    parent = self()
    relay = fn "POST", path, _ -> send(parent, {:p, path}) && {:ok, %{"result" => "deleted"}} end
    uuid = "0f4d3c2a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
    assert {:ok, _} = Firewall.delete_rule(inst(), uuid, relay: relay, audit: audit())
    assert_received {:p, "/api/firewall/filter/del_rule/" <> ^uuid}
  end

  test "the interface filter is form-encoded and must be a plain name" do
    parent = self()

    relay = fn "POST", path, _ ->
      send(parent, {:p, path})
      {:ok, %{"rows" => [], "total" => 0}}
    end

    assert {:ok, _} = Firewall.search_rules(inst(), interface: "opt1", relay: relay)
    assert_received {:p, "/api/firewall/filter/search_rule?interface=opt1&show_all=1"}

    for bad <- ["lan&show_all=0&x=1", "lan#", "a b", String.duplicate("a", 65), %{}],
        do: assert({:error, _} = Firewall.search_rules(inst(), interface: bad, relay: no_relay()))
  end

  test "rule field values must be bounded strings without control characters" do
    for fields <- [
          %{"description" => String.duplicate("a", 1025)},
          %{"description" => "a\nb"},
          %{"source_net" => %{"x" => 1}}
        ],
        do:
          assert(
            {:error, _} =
              Firewall.save_rule(inst(), nil, fields, relay: no_relay(), audit: audit())
          )
  end
end
