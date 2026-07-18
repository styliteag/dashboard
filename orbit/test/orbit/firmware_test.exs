defmodule Orbit.FirmwareTest do
  @moduledoc """
  Firmware orchestration against a private hub instance: the test process
  registers itself as the agent socket (hub_test.exs pattern), the context
  call runs in a Task so the command future can be resolved from here.
  DB-free house style — the audit sink is injected and asserted as messages;
  the real Audit.write path is proven live.
  """

  use ExUnit.Case, async: true

  alias Orbit.Firmware
  alias Orbit.Hub

  @iid 424_242

  setup do
    hub = start_supervised!({Hub, name: nil})
    test_pid = self()
    audit = fn fields -> send(test_pid, {:audit, Map.new(fields)}) end
    %{hub: hub, audit: audit}
  end

  defp inst(attrs \\ %{}) do
    struct(
      Orbit.Instances.Instance,
      Map.merge(%{id: @iid, name: "fwbox", transport: "push", firmware_locked: false}, attrs)
    )
  end

  defp user, do: %{id: 1}

  defp register_agent(hub), do: Hub.register(hub, @iid, %{agent_version: "3.1.8"})

  defp run(fun) do
    task = Task.async(fun)
    assert_receive {:push_frame, %{"type" => "command", "request_id" => rid} = frame}, 1_000
    {task, rid, frame}
  end

  # set_firmware is a cast from the Task process — poll until the merged
  # marker is visible instead of racing the hub mailbox.
  defp await_firmware_cache(hub, pred, attempts \\ 50) do
    fw = Hub.cache_entry(hub, @iid)["firmware"]

    if (fw && pred.(fw)) || attempts == 0 do
      fw
    else
      Process.sleep(10)
      await_firmware_cache(hub, pred, attempts - 1)
    end
  end

  test "check merges the verdict into the hub firmware section and audits ok", ctx do
    :ok = register_agent(ctx.hub)

    {task, rid, frame} =
      run(fn -> Firmware.check(inst(), user(), hub: ctx.hub, audit: ctx.audit) end)

    assert frame["action"] == "firmware.check"

    Hub.resolve_command(ctx.hub, rid, %{
      "success" => true,
      "output" => "OPNsense can be updated",
      "product_version" => "25.1",
      "check_failed" => false
    })

    assert {:ok, "OPNsense can be updated"} = Task.await(task)

    fw = await_firmware_cache(ctx.hub, &(&1["upgrade_available"] == true))
    assert fw["upgrade_available"] == true
    assert fw["updates_available"] == 1
    assert fw["product_version"] == "25.1"
    assert fw["status_msg"] == "OPNsense can be updated"
    assert fw["check_failed"] == false
    assert is_binary(fw["last_check"])

    assert_receive {:audit, %{action: "firmware.check", result: "ok", target_id: @iid}}
  end

  test "check merge keeps cached keys the command did not report", ctx do
    :ok = register_agent(ctx.hub)

    # Simulate a prior agent push with a security-update count.
    Hub.ingest_metrics(ctx.hub, @iid, %{
      "firmware" => %{"product_version" => "24.7", "security_updates" => 2, "branch" => "stable"}
    })

    {task, rid, _} =
      run(fn -> Firmware.check(inst(), user(), hub: ctx.hub, audit: ctx.audit) end)

    Hub.resolve_command(ctx.hub, rid, %{"success" => true, "upgrade_available" => true})
    assert {:ok, _} = Task.await(task)

    fw = await_firmware_cache(ctx.hub, &(&1["upgrade_available"] == true))
    # Reported keys win, unreported cached keys survive (never blank
    # security_updates from the last push — moduledoc contract).
    assert fw["upgrade_available"] == true
    assert fw["security_updates"] == 2
    assert fw["branch"] == "stable"
    assert fw["product_version"] == "24.7"
  end

  test "update success returns truncated output and audits ok", ctx do
    :ok = register_agent(ctx.hub)

    {task, rid, frame} =
      run(fn -> Firmware.update(inst(), user(), hub: ctx.hub, audit: ctx.audit) end)

    assert frame["action"] == "firmware.update"

    Hub.resolve_command(ctx.hub, rid, %{"success" => true, "output" => String.duplicate("x", 300)})

    assert {:ok, msg} = Task.await(task)
    assert String.length(msg) == 200
    assert_receive {:audit, %{action: "firmware.update", result: "ok"}}
  end

  test "update failure returns the agent's output and audits error", ctx do
    :ok = register_agent(ctx.hub)

    {task, rid, _} =
      run(fn -> Firmware.update(inst(), user(), hub: ctx.hub, audit: ctx.audit) end)

    Hub.resolve_command(ctx.hub, rid, %{"success" => false, "output" => "pkg upgrade failed"})

    assert {:error, "pkg upgrade failed"} = Task.await(task)
    assert_receive {:audit, %{action: "firmware.update", result: "error"}}
  end

  test "update refused while firmware_locked: no command, no audit", ctx do
    :ok = register_agent(ctx.hub)

    assert {:error, :locked} =
             Firmware.update(inst(%{firmware_locked: true}), user(),
               hub: ctx.hub,
               audit: ctx.audit
             )

    refute_receive {:push_frame, _}, 50
    refute_receive {:audit, _}, 10
  end

  test "upgrade refused on a direct-poll instance", ctx do
    assert {:error, "series upgrade requires agent mode"} =
             Firmware.upgrade(inst(%{transport: "api"}), user(), hub: ctx.hub, audit: ctx.audit)

    refute_receive {:push_frame, _}, 50
    refute_receive {:audit, _}, 10
  end

  test "check and update answer not_connected without an audit call", ctx do
    assert {:error, :not_connected} =
             Firmware.check(inst(), user(), hub: ctx.hub, audit: ctx.audit)

    assert {:error, :not_connected} =
             Firmware.update(inst(), user(), hub: ctx.hub, audit: ctx.audit)

    refute_receive {:audit, _}, 10
  end

  test "upgrade_status maps running with log lines", ctx do
    :ok = register_agent(ctx.hub)

    {task, rid, frame} = run(fn -> Firmware.upgrade_status(inst(), hub: ctx.hub) end)
    assert frame["action"] == "firmware.upgrade_status"

    Hub.resolve_command(ctx.hub, rid, %{
      "success" => true,
      "status" => "running",
      "log" => ["fetching packages", 42]
    })

    assert %{status: "running", log: ["fetching packages", "42"]} = Task.await(task)
  end

  test "upgrade_status degrades unknown-action and disconnect to unknown", ctx do
    :ok = register_agent(ctx.hub)

    # Old agent: unknown action answers success=false.
    {task, rid, _} = run(fn -> Firmware.upgrade_status(inst(), hub: ctx.hub) end)
    Hub.resolve_command(ctx.hub, rid, %{"success" => false, "output" => "unknown action"})
    assert %{status: "unknown", log: []} = Task.await(task)

    # Disconnected box.
    hub2 = start_supervised!({Hub, name: nil}, id: :hub2)
    assert %{status: "unknown", log: []} = Firmware.upgrade_status(inst(), hub: hub2)
  end

  # Direct-poll (agent-less) firmware goes to the OPNsense client, not the hub.
  test "direct-poll check runs the vendor API via the injected client", ctx do
    Application.put_env(:orbit, :opnsense_req_plug, {Req.Test, __MODULE__})
    on_exit(fn -> Application.delete_env(:orbit, :opnsense_req_plug) end)

    Req.Test.stub(__MODULE__, fn conn ->
      Req.Test.json(conn, %{"status" => "updates available"})
    end)

    client = %Orbit.Poller.OpnsenseClient{
      base_url: "https://box:4444",
      api_key: "k",
      api_secret: "s",
      ssl_verify: false
    }

    di = inst(%{transport: "api", device_type: "opnsense"})

    assert {:ok, "updates available"} =
             Firmware.check(di, user(), client: client, audit: ctx.audit)

    assert_receive {:audit, %{action: "firmware.check", result: "ok"}}
    # No hub command was sent (direct path).
    refute_receive {:push_frame, _}, 10
  end

  test "direct-poll upgrade_status maps the vendor upgradestatus" do
    Application.put_env(:orbit, :opnsense_req_plug, {Req.Test, __MODULE__})
    on_exit(fn -> Application.delete_env(:orbit, :opnsense_req_plug) end)

    Req.Test.stub(__MODULE__, fn conn ->
      Req.Test.json(conn, %{"status" => "done", "log" => "a\nb"})
    end)

    client = %Orbit.Poller.OpnsenseClient{
      base_url: "https://box:4444",
      api_key: "k",
      api_secret: "s",
      ssl_verify: false
    }

    di = inst(%{transport: "api", device_type: "opnsense"})
    assert %{status: "done", log: ["a", "b"]} = Firmware.upgrade_status(di, client: client)
  end
end
