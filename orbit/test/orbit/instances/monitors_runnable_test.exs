defmodule Orbit.Instances.MonitorsRunnableTest do
  @moduledoc """
  Which boxes can actually run ping monitors — the predicate the monitor UI is
  gated on.

  Regression: the Connectivity tab and the Phase-2 monitor controls were gated
  on `agent_mode?/1`, so a Securepoint could neither see nor manage monitors
  even once the probes ran over SSH. The predicate must track the CAPABILITY
  (something on the box can run a ping), not the transport.
  """
  use ExUnit.Case, async: true

  alias Orbit.Instances.Instance

  defp securepoint(attrs \\ []) do
    struct!(
      %Instance{
        id: 1,
        device_type: "securepoint",
        transport: "direct",
        ssh_enabled: true,
        ssh_key_enc: "encrypted-blob",
        ssh_host_key: "ssh-rsa AAAAB3NzaC1yc2E"
      },
      attrs
    )
  end

  test "an agent box can run monitors, as before" do
    assert Instance.monitors_runnable?(%Instance{
             id: 2,
             device_type: "opnsense",
             transport: "push",
             agent_token: "t"
           })
  end

  test "a fully configured Securepoint can run them over SSH" do
    assert Instance.monitors_runnable?(securepoint())
  end

  describe "an incompletely configured Securepoint cannot" do
    test "SSH switched off" do
      refute Instance.monitors_runnable?(securepoint(ssh_enabled: false))
    end

    test "no stored key" do
      refute Instance.monitors_runnable?(securepoint(ssh_key_enc: nil))
    end

    test "no pinned host key — the transport would refuse to connect anyway" do
      refute Instance.monitors_runnable?(securepoint(ssh_host_key: nil))
      refute Instance.monitors_runnable?(securepoint(ssh_host_key: "  "))
    end
  end

  test "a direct-polled OPNsense cannot — nothing on the box runs the ping" do
    refute Instance.monitors_runnable?(%Instance{
             id: 3,
             device_type: "opnsense",
             transport: "direct",
             ssh_enabled: true,
             ssh_key_enc: "blob",
             ssh_host_key: "ssh-rsa AAAA"
           })
  end
end
