defmodule OrbitWeb.InstallScriptTest do
  @moduledoc """
  The pasteable install snippet must survive being pasted on a box that
  already runs an agent.

  Regression (reported from a live OPNsense box): the snippet ended in
  `service orbit_agent start`, which aborts with "daemon: process already
  running, pid: …" when an agent is up — a re-enrollment or a move to another
  dashboard wrote the new config and then quietly left the OLD agent running
  against the OLD dashboard. The systemd half had the same hole in a different
  spelling: `systemctl enable --now` leaves a running unit untouched.
  """
  use ExUnit.Case, async: true

  alias Orbit.Instances.Instance
  alias OrbitWeb.InstanceDetailLive

  defp script(device_type) do
    InstanceDetailLive.install_script(
      %Instance{id: 1, device_type: device_type, transport: "push"},
      {"ENROLL-CODE", ~U[2026-07-20 12:00:00Z]}
    )
  end

  test "the freebsd snippet restarts instead of starting" do
    out = script("opnsense")

    assert out =~ "service orbit_agent restart"
    refute out =~ "service orbit_agent start"
  end

  test "the linux snippet restarts the unit instead of enable --now" do
    out = script("linux")

    assert out =~ "systemctl restart orbit-agent"
    refute out =~ "enable --now"
  end

  test "the enroll code rides the config file, and the service is enabled at boot" do
    out = script("opnsense")

    assert out =~ ~s("enroll_code":"ENROLL-CODE")
    assert out =~ "sysrc orbit_agent_enable=YES"
  end
end
