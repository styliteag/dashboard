defmodule Orbit.HubTest do
  use ExUnit.Case, async: true

  alias Orbit.Hub

  setup do
    hub = start_supervised!({Hub, name: nil})
    %{hub: hub}
  end

  defp register_self(hub, instance_id, meta \\ %{}) do
    Hub.register(
      hub,
      instance_id,
      Map.merge(%{agent_version: "3.1.8", platform: "pfsense"}, meta)
    )
  end

  test "register + get + list_connected", %{hub: hub} do
    :ok = register_self(hub, 7)
    agent = Hub.get(hub, 7)
    assert agent.instance_id == 7
    assert agent.agent_version == "3.1.8"
    assert agent.pid == self()
    assert [%{instance_id: 7}] = Hub.list_connected(hub)
  end

  test "duplicate connect is last-writer-wins: old socket told to close", %{hub: hub} do
    parent = self()

    old =
      spawn(fn ->
        Hub.register(hub, 7, %{})
        send(parent, :registered)

        receive do
          :hub_replaced -> send(parent, :old_replaced)
        end
      end)

    assert_receive :registered
    :ok = register_self(hub, 7)
    assert_receive :old_replaced
    assert Hub.get(hub, 7).pid == self()
  end

  test "identity-aware unregister: a stale pid never evicts the replacement", %{hub: hub} do
    old =
      spawn(fn ->
        Hub.register(hub, 7, %{})

        receive do
          {:unregister_now, from} -> send(from, {:result, Hub.unregister(hub, 7)})
        end
      end)

    # Give the spawned process time to register, then take over.
    Process.sleep(20)
    :ok = register_self(hub, 7)

    send(old, {:unregister_now, self()})
    assert_receive {:result, :stale}
    assert Hub.get(hub, 7).pid == self(), "replacement entry survived the stale unregister"
  end

  test "send_command resolves the future with the agent's result", %{hub: hub} do
    :ok = register_self(hub, 7)

    task =
      Task.async(fn ->
        Hub.send_command_on(hub, 7, "ping", %{}, 1_000)
      end)

    assert_receive {:push_frame, %{"type" => "command", "request_id" => rid, "action" => "ping"}}
    Hub.resolve_command(hub, rid, %{"success" => true, "output" => "pong"})
    assert Task.await(task) == %{"success" => true, "output" => "pong"}
  end

  test "send_command times out with the python-parity answer", %{hub: hub} do
    :ok = register_self(hub, 7)
    result = Hub.send_command_on(hub, 7, "ping", %{}, 50)
    assert result == %{"success" => false, "output" => "command timed out"}
    assert_receive {:push_frame, %{"request_id" => rid}}
    # A late resolve after the timeout is dropped silently.
    Hub.resolve_command(hub, rid, %{"success" => true})
    refute_receive {:command_result, _, _}, 50
  end

  test "send_command to a disconnected instance", %{hub: hub} do
    assert {:error, :not_connected} = Hub.send_command_on(hub, 99, "ping", %{}, 100)
  end

  test "regression: 4-arg send_command goes to the global hub, not whereis(id)" do
    # A double-default head once bound server=instance_id → GenServer.whereis(7)
    # FunctionClauseError on the live ping route.
    assert {:error, :not_connected} = Hub.send_command(424_242, "ping", %{}, 50)
  end

  test "send_config pushes a config_update to a connected agent", %{hub: hub} do
    :ok = register_self(hub, 7)
    Hub.send_config(hub, 7, %{"push_interval" => 45})
    assert_receive {:push_frame, %{"type" => "config_update", "data" => %{"push_interval" => 45}}}
  end

  test "send_config to a disconnected instance is a no-op", %{hub: hub} do
    :ok = Hub.send_config(hub, 99, %{"push_interval" => 45})
    refute_receive {:push_frame, _}, 50
  end

  test "push/pong counters", %{hub: hub} do
    :ok = register_self(hub, 7)
    Hub.record_push(hub, 7)
    Hub.record_push(hub, 7)
    Hub.record_pong(hub, 7)
    agent = Hub.get(hub, 7)
    assert agent.pushes == 2
    assert agent.pongs == 1
    assert %DateTime{} = agent.last_push_at
  end
end
