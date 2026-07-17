defmodule Orbit.BulkTest do
  @moduledoc """
  Bulk actions against a private hub (firmware_test.exs pattern): the test
  process is the agent socket, the run happens in a Task so command futures
  can be resolved from here. DB-free — the visible-instances source and the
  audit sink are injected.
  """

  use ExUnit.Case, async: true

  alias Orbit.Bulk
  alias Orbit.Hub

  setup do
    hub = start_supervised!({Hub, name: nil})
    test_pid = self()
    audit = fn fields -> send(test_pid, {:audit, Map.new(fields)}) end
    %{hub: hub, audit: audit}
  end

  defp inst(id, attrs \\ %{}) do
    struct(
      Orbit.Instances.Instance,
      Map.merge(
        %{id: id, name: "box#{id}", transport: "push", firmware_locked: false},
        attrs
      )
    )
  end

  defp user, do: %{id: 1}

  defp run(ctx, ids, action, visible) do
    Bulk.run(ids, action, user(),
      hub: ctx.hub,
      audit: ctx.audit,
      list: fn _user -> visible end
    )
  end

  test "unknown action refused before any work", ctx do
    assert {:error, :unknown_action} = run(ctx, [1], "rm_rf", [inst(1)])
    refute_receive {:audit, _}, 10
  end

  test "out-of-scope ids are silently dropped (no result, no audit)", ctx do
    :ok = Hub.register(ctx.hub, 1, %{})

    task = Task.async(fn -> run(ctx, [1, 99], "reboot", [inst(1)]) end)
    assert_receive {:push_frame, %{"action" => "reboot", "request_id" => rid}}, 1_000
    Hub.resolve_command(ctx.hub, rid, %{"success" => true, "output" => "rebooting"})

    assert {:ok, [r]} = Task.await(task)
    assert r.instance_id == 1
    assert r.success
    assert_receive {:audit, %{action: "bulk.reboot", result: "ok", target_id: 1}}
    refute_receive {:audit, %{target_id: 99}}, 10
  end

  test "firmware update refused on locked instances without a command", ctx do
    assert {:ok, [r]} =
             run(ctx, [1], "firmware_update", [inst(1, %{firmware_locked: true})])

    refute r.success
    assert r.message =~ "locked"
    refute_receive {:push_frame, _}, 10
    assert_receive {:audit, %{action: "bulk.firmware_update", result: "error"}}
  end

  test "series upgrade refused for direct-poll instances", ctx do
    assert {:ok, [r]} = run(ctx, [1], "firmware_upgrade", [inst(1, %{transport: "api"})])
    refute r.success
    assert r.message =~ "requires agent mode"
  end

  test "disconnected agents answer per-instance, not by failing the batch", ctx do
    :ok = Hub.register(ctx.hub, 1, %{})

    task = Task.async(fn -> run(ctx, [1, 2], "firmware_check", [inst(1), inst(2)]) end)
    assert_receive {:push_frame, %{"action" => "firmware.check", "request_id" => rid}}, 1_000
    Hub.resolve_command(ctx.hub, rid, %{"success" => true, "output" => "no updates"})

    assert {:ok, results} = Task.await(task, 5_000)
    by_id = Map.new(results, &{&1.instance_id, &1})
    assert by_id[1].success
    refute by_id[2].success
    assert by_id[2].message == "agent not connected"
  end
end
