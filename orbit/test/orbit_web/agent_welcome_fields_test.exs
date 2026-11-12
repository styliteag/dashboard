defmodule OrbitWeb.AgentWelcomeFieldsTest do
  @moduledoc """
  Extension point `:agent_welcome_fields`: per-instance settings sent with
  every welcome (open keys win). A firewall gets the vendored Checkmk script
  (`checkmk.update`) only while its welcome asks for the script; without the
  hook nothing changes for it.
  """

  use Orbit.DataCase, async: false

  import OrbitWeb.TestHooks, only: [put_hook: 2, delete_hook: 1]

  alias Orbit.Accounts.Group
  alias Orbit.AgentBinding
  alias Orbit.Hub
  alias OrbitWeb.AgentSocket

  setup do
    group = Repo.insert!(%Group{name: "welcome-#{System.unique_integer([:positive])}"})

    {:ok, inst} =
      Orbit.Instances.create_instance(
        %{"name" => "fw-#{System.unique_integer([:positive])}", "device_type" => "pfsense"},
        group.id
      )

    {:ok, inst, _token} = AgentBinding.enable(inst)
    on_exit(fn -> Hub.evict(inst.id) end)
    {:ok, inst: inst}
  end

  defp connect(inst) do
    {:ok, state} = AgentSocket.init(%{instance: inst})

    hello =
      Jason.encode!(%{
        "type" => "hello",
        "agent_version" => "9.9.9",
        "platform" => "pfsense",
        "checkmk_sha256" => ""
      })

    {:push, {:text, welcome}, _state} = AgentSocket.handle_in({hello, [opcode: :text]}, state)
    Jason.decode!(welcome)
  end

  test "unset: plain welcome, no script for a firewall", %{inst: inst} do
    delete_hook(:agent_welcome_fields)

    welcome = connect(inst)

    refute Map.has_key?(welcome, "checkmk")
    refute_receive {:push_frame, %{"action" => "checkmk.update"}}, 300
  end

  test "hook fields ride the welcome; open keys win; the script follows", %{inst: inst} do
    put_hook(:agent_welcome_fields, [OrbitWeb.TestHooks.WelcomeFields])

    welcome = connect(inst)

    assert welcome["checkmk"] == true
    assert welcome["push_interval"] != 1
    assert_receive {:push_frame, %{"action" => "checkmk.update", "params" => params}}, 2_000
    assert params["sha256"] == Orbit.Agent.Package.checkmk_sha256(:firewall)
    assert params["signature"] != ""
  end
end
