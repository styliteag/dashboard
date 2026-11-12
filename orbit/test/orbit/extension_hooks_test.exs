defmodule Orbit.ExtensionHooksTest do
  @moduledoc """
  Core-side extension points (docs/extension-points.md): `:notification_suppressors`
  and `:extra_children`. async: false — the hooks are global app env.
  """

  use ExUnit.Case, async: false

  import OrbitWeb.TestHooks, only: [put_hook: 2, delete_hook: 1]

  alias Orbit.Notifier
  alias OrbitWeb.TestHooks.Suppressor

  describe ":notification_suppressors" do
    test "unset: the alert reaches dispatch (routing decides, nothing suppressed)" do
      delete_hook(:notification_suppressors)

      results = Notifier.send_notification("t", "m", nil, "warn", "test:suppressed")

      # No channel is subscribed by default → dispatch answers per channel.
      assert length(results) == 3
      assert Enum.all?(results, &(&1.status == "skipped"))
    end

    test "a suppressor answering true drops the alert before dispatch" do
      put_hook(:notification_suppressors, [Suppressor])

      assert Notifier.send_notification("t", "m", 7, "warn", "test:suppressed") == []
      assert_received {:suppress?, 7, "test:suppressed"}
    end

    test "a suppressor answering false lets the alert through" do
      put_hook(:notification_suppressors, [Suppressor])

      results = Notifier.send_notification("t", "m", nil, "warn", "cpu")

      assert length(results) == 3
      assert_received {:suppress?, nil, "cpu"}
    end
  end

  describe ":checkmk_output_receivers" do
    @fixture Path.join([__DIR__, "..", "support", "fixtures", "checkmk_linux.b64"])
             |> Path.expand()
             |> File.read!()
             |> String.trim()

    setup do
      put_hook(:checkmk_receiver_test_pid, self())
      %{hub: start_supervised!({Orbit.Hub, name: nil})}
    end

    defp push(hub, id, raw) do
      Orbit.Hub.ingest_metrics(hub, id, %{"checkmk_raw" => raw})
      # A call after the cast: the ingest has run once this returns.
      Orbit.Hub.cache_entry(hub, id)
    end

    defp fresh, do: %{"output_gz_b64" => @fixture, "interval" => 60}

    test "unset: ingest runs as before, nothing is called", %{hub: hub} do
      delete_hook(:checkmk_output_receivers)

      assert push(hub, 7, fresh())["checkmk_output"] =~ "<<<check_mk>>>"
      refute_received {:checkmk_output, _, _, _}
    end

    test "a fresh output reaches every receiver with its interval", %{hub: hub} do
      put_hook(:checkmk_output_receivers, [OrbitWeb.TestHooks.CheckmkReceiver])

      push(hub, 7, fresh())

      assert_received {:checkmk_output, 7, "<<<check_mk>>>" <> _, %{interval: 60}}
    end

    test "a push without a run of the script calls nothing", %{hub: hub} do
      put_hook(:checkmk_output_receivers, [OrbitWeb.TestHooks.CheckmkReceiver])

      push(hub, 7, fresh())
      assert_received {:checkmk_output, 7, _, _}
      push(hub, 7, %{})

      refute_received {:checkmk_output, 7, _, _}
    end

    test "a failed firewall run reaches the receivers with its reason, no output",
         %{hub: hub} do
      put_hook(:checkmk_output_receivers, [OrbitWeb.TestHooks.CheckmkReceiver])

      Orbit.Hub.ingest_metrics(hub, 7, %{
        "checkmk_status" => %{"ok" => false, "reason" => "only 1 section", "interval" => 60}
      })

      assert Orbit.Hub.cache_entry(hub, 7)["checkmk_status"]["reason"] == "only 1 section"

      assert_received {:checkmk_output, 7, "",
                       %{failed: "only 1 section", interval: 60, transport_only: true}}
    end

    test "a raising receiver never breaks ingest", %{hub: hub} do
      put_hook(:checkmk_output_receivers, [OrbitWeb.TestHooks.CheckmkReceiver])

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          assert push(hub, 13, fresh())["status"]["memory"]["total_mb"] == 1895
        end)

      assert log =~ "checkmk.receiver_failed"
      refute log =~ "<<<"
      assert push(hub, 7, fresh())["checkmk_output"]
      assert_received {:checkmk_output, 7, _, _}
    end
  end

  describe ":extra_children" do
    test "unset: no extra children" do
      delete_hook(:extra_children)
      assert Orbit.Application.extra_children() == []
    end

    test "returns the configured child specs unchanged" do
      specs = [{Agent, fn -> :ok end}, {Task.Supervisor, name: :hook_test_tasks}]
      put_hook(:extra_children, specs)

      assert Orbit.Application.extra_children() == specs
    end
  end
end
