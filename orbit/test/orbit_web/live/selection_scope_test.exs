defmodule OrbitWeb.SelectionScopeTest do
  @moduledoc """
  Selection rules: a GLOBAL rule (no instance) steers notifications for
  every tenant, so only a superadmin may set or clear one; per-instance rules
  are scope-checked on delete exactly like on add. A group-scoped admin
  forging a delete_rule event for a global rule or another tenant's
  instance changes nothing.
  """
  use OrbitWeb.ConnCase, async: false

  alias Orbit.Selection
  alias OrbitWeb.SelectionLive

  defp socket(user) do
    Phoenix.Component.assign(%Phoenix.LiveView.Socket{}, current_user: user, error: nil)
  end

  defp user!(superadmin?) do
    {:ok, u} =
      Orbit.Accounts.Admin.create_user(%{
        "username" => "sel-#{System.unique_integer([:positive])}",
        "password" => "long-enough-pw",
        "role" => "admin",
        "is_superadmin" => superadmin?
      })

    u
  end

  defp admin, do: user!(false)
  defp root, do: user!(true)

  defp global_rules,
    do: for(r <- Selection.list_rules(), r.instance_id == nil, do: {r.consumer, r.selector})

  test "a group-scoped admin can neither clear nor set a global rule" do
    Selection.set_rule("mattermost", "availability", "include", nil)

    {:noreply, s} =
      SelectionLive.handle_event(
        "delete_rule",
        %{"consumer" => "mattermost", "selector" => "availability", "instance_id" => ""},
        socket(admin())
      )

    assert s.assigns.error
    assert {"mattermost", "availability"} in global_rules()

    {:noreply, s} =
      SelectionLive.handle_event(
        "add_rule",
        %{
          "rule" => %{
            "consumer" => "telegram",
            "selector" => "availability",
            "mode" => "include",
            "instance_id" => ""
          }
        },
        socket(admin())
      )

    assert s.assigns.error
    refute {"telegram", "availability"} in global_rules()
  end

  test "an out-of-scope instance rule cannot be deleted" do
    {:noreply, s} =
      SelectionLive.handle_event(
        "delete_rule",
        %{"consumer" => "mattermost", "selector" => "availability", "instance_id" => "999999"},
        socket(admin())
      )

    assert s.assigns.error
  end

  test "a superadmin may clear a global rule" do
    Selection.set_rule("mattermost", "availability", "include", nil)

    {:noreply, s} =
      SelectionLive.handle_event(
        "delete_rule",
        %{"consumer" => "mattermost", "selector" => "availability", "instance_id" => ""},
        socket(root())
      )

    refute s.assigns.error
    refute {"mattermost", "availability"} in global_rules()
  end
end
