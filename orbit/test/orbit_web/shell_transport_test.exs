defmodule OrbitWeb.ShellTransportTest do
  @moduledoc """
  The transport gate of the shell WS route — the LAST gate, and the only one
  that knows about transports.

  Everything above it (feature gate, session, scope, per-instance opt-in) is
  identical for an agent box and an SSH box; this decides which PTY to attach
  to, or refuses with 4404. The SSH path must not be a wider door than the
  agent path: it requires the same per-instance opt-in plus a pinned host key,
  because that transport is fail-closed and an unpinned key would mean
  attaching a root shell to an unverified peer.
  """
  use ExUnit.Case, async: true

  alias Orbit.Instances.Instance
  alias OrbitWeb.ShellWSController

  defp inst(attrs) do
    struct!(
      %Instance{
        id: 4242,
        device_type: "securepoint",
        ssh_enabled: true,
        ssh_key_enc: "encrypted-blob",
        ssh_host_key: "ssh-rsa AAAAB3NzaC1yc2E"
      },
      attrs
    )
  end

  describe "SSH shell eligibility" do
    test "a fully configured Securepoint qualifies" do
      assert ShellWSController.ssh_shell_possible?(inst([]))
    end

    test "an unpinned host key does NOT qualify — no root shell to an unverified peer" do
      refute ShellWSController.ssh_shell_possible?(inst(ssh_host_key: nil))
      refute ShellWSController.ssh_shell_possible?(inst(ssh_host_key: ""))
      refute ShellWSController.ssh_shell_possible?(inst(ssh_host_key: "   "))
    end

    test "no stored key does not qualify" do
      refute ShellWSController.ssh_shell_possible?(inst(ssh_key_enc: nil))
    end

    test "SSH switched off for the instance does not qualify" do
      refute ShellWSController.ssh_shell_possible?(inst(ssh_enabled: false))
    end

    test "the SSH path is Securepoint-only — it never becomes a back door for other kinds" do
      for kind <- ~w(opnsense pfsense linux proxmox) do
        refute ShellWSController.ssh_shell_possible?(inst(device_type: kind)),
               "#{kind} must attach to its agent, not to an SSH shell"
      end
    end
  end
end
