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
