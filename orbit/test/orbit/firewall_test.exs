defmodule Orbit.FirewallTest do
  @moduledoc """
  Firewall-rules operations with an injected relay (opts[:relay]) — the
  request method/path/body and the OPNsense envelope mapping are asserted
  without a real box. normalize_rule's nested-field handling is unit-tested.
  """

  use ExUnit.Case, async: true

  alias Orbit.Firewall

  defp inst, do: %Orbit.Instances.Instance{id: 7, name: "opn1", device_type: "opnsense"}

  defp audit_sink(pid), do: fn fields -> send(pid, {:audit, Map.new(fields)}) end

  test "search_rules posts search_rule and normalizes rows" do
    relay = fn "POST", path, _body ->
      assert path =~ "/api/firewall/filter/search_rule"
      {:ok, %{"rows" => [%{"uuid" => "u1", "action" => "pass", "enabled" => "1"}], "total" => 1}}
    end

    assert {:ok, %{rows: [rule], total: 1}} = Firewall.search_rules(inst(), relay: relay)
    assert rule.uuid == "u1"
    assert rule.action == "pass"
    assert rule.enabled == true
    assert rule.editable == true
  end

  test "toggle_rule hits the toggle endpoint with the on/off suffix and audits ok" do
    parent = self()

    relay = fn "POST", path, _body ->
      send(parent, {:path, path})
      {:ok, %{"result" => "saved"}}
    end

    assert {:ok, _} =
             Firewall.toggle_rule(inst(), "u1", false, relay: relay, audit: audit_sink(parent))

    assert_received {:path, "/api/firewall/filter/toggle_rule/u1/0"}
    assert_received {:audit, %{action: "firewall.rule.toggle", result: "ok"}}
  end

  test "delete_rule + apply map their endpoints" do
    parent = self()
    relay = fn "POST", path, _b -> send(parent, {:p, path}) && {:ok, %{"result" => "deleted"}} end
    assert {:ok, _} = Firewall.delete_rule(inst(), "u9", relay: relay, audit: audit_sink(parent))
    assert_received {:p, "/api/firewall/filter/del_rule/u9"}

    relay2 = fn "POST", path, _b -> send(parent, {:p, path}) && {:ok, %{"status" => "ok"}} end
    assert {:ok, _} = Firewall.apply(inst(), relay: relay2, audit: audit_sink(parent))
    assert_received {:p, "/api/firewall/filter/apply"}
  end

  test "an upstream validation failure is an error result" do
    relay = fn "POST", _path, _b ->
      {:ok, %{"result" => "failed", "validations" => %{"x" => "bad"}}}
    end

    assert {:error, msg} =
             Firewall.toggle_rule(inst(), "u1", true, relay: relay, audit: audit_sink(self()))

    assert msg =~ "validation"
    assert_received {:audit, %{result: "error"}}
  end

  test "normalize_rule reads nested select-option fields and disabled state" do
    row = %{
      "uuid" => "u2",
      "disabled" => "1",
      "action" => %{"pass" => %{"value" => "Pass", "selected" => 1}},
      "interface" => %{"wan" => %{"value" => "WAN", "selected" => 1}},
      "legacy" => "0"
    }

    r = Firewall.normalize_rule(row)
    assert r.enabled == false
    assert r.action == "Pass"
    assert r.interfaces == "WAN"
    assert r.editable == true
  end

  test "search on a disconnected agent (no relay injected) answers not connected" do
    hub = start_supervised!({Orbit.Hub, name: nil})
    di = %{inst() | transport: "push"}
    assert {:error, "agent not connected"} = Firewall.search_rules(di, hub: hub)
  end
end
