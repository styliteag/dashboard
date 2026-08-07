defmodule OrbitWeb.Components.InstanceTabsTest do
  @moduledoc """
  Hidden-vs-disabled tab rules (UI/UX review U-M8): device-class gates hide
  a tab, box-state gates disable it with a reason, and `tabs_for/2` (the
  routing truth) admits only usable tabs.
  """
  use ExUnit.Case, async: true

  alias Orbit.Instances.Instance
  alias OrbitWeb.Components.InstanceTabs

  defp inst(attrs) do
    struct!(
      %Instance{
        id: 1,
        name: "box",
        device_type: "opnsense",
        transport: "push",
        ssh_enabled: false
      },
      attrs
    )
  end

  defp keys(tabs), do: Enum.map(tabs, &elem(&1, 0))

  defp reason(inst, key) do
    {_k, _l, _kind, reason} = Enum.find(InstanceTabs.all_tabs_for(inst), &(elem(&1, 0) == key))
    reason
  end

  test "an agent-mode opnsense box has every tab enabled" do
    tabs = InstanceTabs.all_tabs_for(inst(%{}))
    assert Enum.all?(tabs, fn {_k, _l, _kind, reason} -> is_nil(reason) end)
    assert "capture" in keys(tabs)
    assert "firewall" in keys(tabs)
  end

  test "state gates disable with a reason instead of hiding" do
    direct = inst(%{transport: "direct"})

    assert reason(direct, "capture") =~ "agent"
    assert reason(direct, "connectivity") =~ "agent"
    # the disabled tabs still show in the bar…
    assert "capture" in keys(InstanceTabs.all_tabs_for(direct))
    # …but are NOT valid navigation targets
    refute "capture" in keys(InstanceTabs.tabs_for(direct))
    refute "connectivity" in keys(InstanceTabs.tabs_for(direct))
  end

  test "device-class gates hide the tab entirely" do
    sp = inst(%{device_type: "securepoint", transport: "direct"})
    sp_keys = keys(InstanceTabs.all_tabs_for(sp))

    refute "capture" in sp_keys
    refute "agent" in sp_keys
    refute "firewall" in sp_keys
  end

  test "a securepoint with SSH monitors gets connectivity enabled" do
    sp =
      inst(%{
        device_type: "securepoint",
        transport: "direct",
        ssh_enabled: true,
        ssh_key_enc: "enc",
        ssh_host_key: "ssh-ed25519 AAA"
      })

    assert is_nil(reason(sp, "connectivity"))
    assert "connectivity" in keys(InstanceTabs.tabs_for(sp))
  end
end
