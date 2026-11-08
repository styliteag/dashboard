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

  describe "evict/2 (binding revoked)" do
    # Regression: the LiveView called Hub.unregister/1 after disable/uninstall
    # — identity-checked against ITS pid, so it answered :stale and the agent
    # socket stayed on the roster, kept pushing and kept receiving commands.
    defp spawn_socket(hub, instance_id) do
      parent = self()

      pid =
        spawn(fn ->
          :ok = Hub.register(hub, instance_id, %{})
          send(parent, :registered)
          forward_until_evicted(parent)
        end)

      assert_receive :registered
      pid
    end

    # A fake agent socket: report every message, stop like the real one does
    # on :hub_evicted.
    defp forward_until_evicted(parent) do
      receive do
        :hub_evicted ->
          send(parent, {:socket_got, :hub_evicted})

        msg ->
          send(parent, {:socket_got, msg})
          forward_until_evicted(parent)
      end
    end

    test "closes the socket even when called from another process", %{hub: hub} do
      _socket = spawn_socket(hub, 7)
      # The caller is NOT the socket — unregister would be :stale here.
      assert Hub.unregister(hub, 7) == :stale
      assert Hub.get(hub, 7) != nil

      assert Hub.evict(hub, 7) == :ok

      assert_receive {:socket_got, :hub_evicted}
      assert Hub.get(hub, 7) == nil
      assert Hub.list_connected(hub) == []
    end

    test "nothing routes to the evicted socket afterwards", %{hub: hub} do
      _socket = spawn_socket(hub, 7)
      :ok = Hub.evict(hub, 7)
      assert_receive {:socket_got, :hub_evicted}

      assert {:error, :not_connected} = Hub.send_command_on(hub, 7, "ping", %{}, 100)
      assert {:error, :not_connected} = Hub.open_tunnel(hub, 7, %{})

      # A push frame the socket still had queued must not resurrect it.
      Hub.record_push(hub, 7)
      assert Hub.get(hub, 7) == nil
    end

    test "open tunnel streams are closed toward their consumers", %{hub: hub} do
      _socket = spawn_socket(hub, 7)
      {:ok, stream} = Hub.open_tunnel(hub, 7, %{"kind" => "shell"})

      :ok = Hub.evict(hub, 7)

      assert_receive {:tunnel, ^stream, "close", _frame}
    end

    test "the evicted socket's own late unregister is a no-op", %{hub: hub} do
      old =
        spawn(fn ->
          Hub.register(hub, 7, %{})

          receive do
            {:unregister_now, from} -> send(from, {:result, Hub.unregister(hub, 7)})
          end
        end)

      Process.sleep(20)
      :ok = Hub.evict(hub, 7)
      send(old, {:unregister_now, self()})
      assert_receive {:result, :stale}
    end

    test "absent instance: :not_connected, nothing else happens", %{hub: hub} do
      :ok = register_self(hub, 8)
      assert Hub.evict(hub, 7) == :not_connected
      assert Hub.get(hub, 8).pid == self()
      refute_receive :hub_evicted, 50
    end
  end
end
