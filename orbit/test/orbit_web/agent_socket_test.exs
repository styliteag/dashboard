defmodule OrbitWeb.AgentSocketTest do
  @moduledoc """
  The agent socket honours binding revocation: auth runs only at the WS
  upgrade, so a revoked binding must close the live socket (Hub.evict →
  :hub_evicted → close 4003) and a hello on a binding revoked between the
  upgrade and the hello must not register. Uses the global hub — the socket
  callbacks talk to it directly; the test process plays the socket.
  """

  use Orbit.DataCase, async: false

  alias Orbit.Accounts.Group
  alias Orbit.AgentBinding
  alias Orbit.Hub
  alias OrbitWeb.AgentSocket

  setup do
    group = Repo.insert!(%Group{name: "sock-#{System.unique_integer([:positive])}"})

    {:ok, inst} =
      Orbit.Instances.create_instance(
        %{"name" => "sock-#{System.unique_integer([:positive])}", "device_type" => "opnsense"},
        group.id
      )

    {:ok, inst, _token} = AgentBinding.enable(inst)
    on_exit(fn -> Hub.evict(inst.id) end)
    {:ok, inst: inst}
  end

  defp hello, do: Jason.encode!(%{"type" => "hello", "agent_version" => "9.9.9"})

  test "an evicted socket closes with 4003", %{inst: inst} do
    {:ok, state} = AgentSocket.init(%{instance: inst})
    :ok = Hub.register(inst.id, %{})

    # The LiveView process disables the agent — not the socket process.
    {:ok, _} = fn -> AgentBinding.disable(inst) end |> Task.async() |> Task.await()

    assert_receive :hub_evicted

    assert {:stop, :normal, {4003, _reason}, _state} =
             AgentSocket.handle_info(:hub_evicted, state)

    assert Hub.get(inst.id) == nil
  end

  test "hello on a binding revoked after the upgrade is refused", %{inst: inst} do
    {:ok, state} = AgentSocket.init(%{instance: inst})
    {:ok, _} = AgentBinding.disable(inst)

    assert {:stop, :normal, {4003, _reason}, _state} =
             AgentSocket.handle_in({hello(), [opcode: :text]}, state)

    assert Hub.get(inst.id) == nil
  end

  test "hello after a token rotation is refused for the old token", %{inst: inst} do
    {:ok, state} = AgentSocket.init(%{instance: inst})
    {:ok, _rotated, _new} = AgentBinding.enable(inst)

    assert {:stop, :normal, {4003, _reason}, _state} =
             AgentSocket.handle_in({hello(), [opcode: :text]}, state)

    assert Hub.get(inst.id) == nil
  end

  test "frames before hello are dropped: an unregistered socket cannot be evicted",
       %{inst: inst} do
    {:ok, state} = AgentSocket.init(%{instance: inst})
    metrics = Jason.encode!(%{"type" => "metrics", "data" => %{"ts" => "2026-11-08T10:00:00Z"}})

    assert {:ok, ^state} = AgentSocket.handle_in({metrics, [opcode: :text]}, state)

    assert Repo.get!(Orbit.Instances.Instance, inst.id).last_success_at == nil
  end

  test "a stale-token hello does not kick the current socket", %{inst: inst} do
    {:ok, stale} = AgentSocket.init(%{instance: inst})
    {:ok, rotated, _token} = AgentBinding.enable(inst)
    {:ok, _current} = AgentSocket.init(%{instance: rotated})
    parent = self()

    current =
      spawn(fn ->
        :ok = Hub.register(inst.id, %{})
        send(parent, :registered)

        receive do
          msg -> send(parent, {:current_got, msg})
        end
      end)

    assert_receive :registered

    assert {:stop, :normal, {4003, _}, _} =
             AgentSocket.handle_in({hello(), [opcode: :text]}, stale)

    refute_receive {:current_got, _}, 100
    assert Hub.get(inst.id).pid == current
  end
end
