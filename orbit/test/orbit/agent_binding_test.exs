defmodule Orbit.AgentBindingTest do
  @moduledoc """
  Every agent-binding transition (enable/rotate, disable — also the
  uninstall path —, delete) closes the live agent socket. Regression: the
  callers used Hub.unregister/1 from the LiveView process; unregister is
  pid-identity-checked, answered :stale and did nothing, so a revoked agent
  kept pushing (stamping last_success_at, clearing maintenance) and kept
  receiving commands/tunnels until it happened to reconnect.

  The test process plays the agent socket (it registers itself); the
  transitions run in a separate process, like the LiveView.
  """

  use Orbit.DataCase, async: false

  alias Orbit.Accounts.Group
  alias Orbit.AgentBinding
  alias Orbit.Hub
  alias Orbit.Instances.Instance

  setup do
    hub = start_supervised!({Hub, name: nil})
    group = Repo.insert!(%Group{name: "binding-#{System.unique_integer([:positive])}"})

    {:ok, inst} =
      Orbit.Instances.create_instance(
        %{"name" => "bind-#{System.unique_integer([:positive])}", "device_type" => "opnsense"},
        group.id
      )

    {:ok, inst, token} = AgentBinding.enable(inst, hub)
    {:ok, hub: hub, inst: inst, token: token}
  end

  # Run `fun` in another process (the LiveView in production).
  defp elsewhere(fun), do: fun |> Task.async() |> Task.await()

  defp connect(hub, inst), do: :ok = Hub.register(hub, inst.id, %{})

  test "disable revokes the token and evicts the socket", %{hub: hub, inst: inst} do
    connect(hub, inst)

    assert {:ok, %Instance{transport: "direct", agent_token: nil}} =
             elsewhere(fn -> AgentBinding.disable(inst, hub) end)

    assert_receive :hub_evicted
    assert Hub.get(hub, inst.id) == nil
    assert {:error, :not_connected} = Hub.send_command_on(hub, inst.id, "ping", %{}, 100)
  end

  test "token rotation (enable on a bound instance) evicts the old socket", ctx do
    connect(ctx.hub, ctx.inst)

    {:ok, rotated, new_token} = elsewhere(fn -> AgentBinding.enable(ctx.inst, ctx.hub) end)

    assert new_token != ctx.token
    assert rotated.agent_token == new_token
    assert_receive :hub_evicted
    assert Hub.get(ctx.hub, ctx.inst.id) == nil
  end

  test "delete evicts the socket", %{hub: hub, inst: inst} do
    connect(hub, inst)

    {:ok, deleted} = elsewhere(fn -> AgentBinding.delete(inst, hub) end)

    assert deleted.deleted_at
    assert_receive :hub_evicted
    assert Hub.get(hub, inst.id) == nil
  end

  test "transitions without a connected agent still persist", %{hub: hub, inst: inst} do
    assert {:ok, %Instance{transport: "direct"}} = AgentBinding.disable(inst, hub)
    refute_receive :hub_evicted, 50
  end

  describe "current?/2 and instance_for_token/1 (the socket's view of its binding)" do
    test "live push binding with the matching token", %{inst: inst, token: token} do
      assert AgentBinding.current?(inst.id, token)
      assert %Instance{id: id} = AgentBinding.instance_for_token(token)
      assert id == inst.id
    end

    test "rotated, disabled or deleted bindings are no longer current", ctx do
      {:ok, _, new_token} = AgentBinding.enable(ctx.inst, ctx.hub)
      refute AgentBinding.current?(ctx.inst.id, ctx.token)
      assert AgentBinding.instance_for_token(ctx.token) == nil
      assert AgentBinding.current?(ctx.inst.id, new_token)

      {:ok, disabled} = AgentBinding.disable(ctx.inst, ctx.hub)
      refute AgentBinding.current?(ctx.inst.id, new_token)

      {:ok, rebound, token3} = AgentBinding.enable(disabled, ctx.hub)
      {:ok, _} = AgentBinding.delete(rebound, ctx.hub)
      refute AgentBinding.current?(ctx.inst.id, token3)
      assert AgentBinding.instance_for_token(token3) == nil
    end

    test "nil or empty tokens never match", %{inst: inst} do
      refute AgentBinding.current?(inst.id, nil)
      refute AgentBinding.current?(inst.id, "")
      assert AgentBinding.instance_for_token(nil) == nil
    end
  end
end
