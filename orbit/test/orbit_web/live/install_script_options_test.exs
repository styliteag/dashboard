defmodule OrbitWeb.InstallScriptOptionsTest do
  @moduledoc """
  The install snippet can target another dashboard URL (name and port) and
  skip TLS verification for a lab CA the box does not trust yet.
  """
  use ExUnit.Case, async: true

  alias Orbit.Instances.Instance
  alias OrbitWeb.InstanceDetailLive

  @code {"CODE", ~U[2026-07-20 12:00:00Z]}

  defp script(type, opts) do
    InstanceDetailLive.install_script(
      %Instance{id: 1, device_type: type, transport: "push"},
      @code,
      opts
    )
  end

  test "base_url drives the downloads and the websocket URL, port included" do
    out = script("linux", base_url: "https://dash.lab.home:8443")

    assert out =~ "https://dash.lab.home:8443/api/agent/script-linux"
    assert out =~ ~s("dashboard_url":"wss://dash.lab.home:8443/api/ws/agent")
  end

  test "a default port is not repeated in the websocket URL" do
    assert script("linux", base_url: "https://dash.lab.home") =~
             ~s("dashboard_url":"wss://dash.lab.home/api/ws/agent")
  end

  test "insecure adds -k to every curl and insecure_tls to the config (linux)" do
    out = script("linux", base_url: "https://d.example:8443", insecure: true)

    assert out =~ "curl -kfsSo /usr/local/orbit-agent/orbit_agent.py"
    assert out =~ "curl -kfsSo /etc/systemd/system/orbit-agent.service"
    refute out =~ "curl -fsSo"
    assert out =~ ~s("insecure_tls":true)
  end

  test "insecure on freebsd skips peer verification in fetch" do
    out = script("opnsense", base_url: "https://d.example", insecure: true)

    assert out =~ "fetch --no-verify-peer -o /usr/local/orbit-agent/orbit_agent.py"
    assert out =~ ~s("insecure_tls":true)
  end

  test "defaults are unchanged: verified, no insecure_tls" do
    out = script("linux", [])

    assert out =~ "curl -fsSo"
    refute out =~ "insecure_tls"
    refute out =~ " -k"
  end
end
