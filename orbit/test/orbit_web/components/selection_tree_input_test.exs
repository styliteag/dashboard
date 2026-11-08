defmodule OrbitWeb.Components.SelectionTreeInputTest do
  @moduledoc """
  Settings → selection tree: category/service toggles validate the selector
  like the rules page (`Selection.valid_selector?/2`), a global category
  toggle is superadmin-only, and a non-numeric instance id is ignored
  instead of crashing the LiveView.
  """
  use OrbitWeb.ConnCase, async: false

  alias Orbit.Selection
  alias OrbitWeb.Components.SelectionTree

  defp user!(superadmin?) do
    {:ok, u} =
      Orbit.Accounts.Admin.create_user(%{
        "username" => "tree-#{System.unique_integer([:positive])}",
        "password" => "long-enough-pw",
        "role" => "admin",
        "is_superadmin" => superadmin?
      })

    u
  end

  defp socket(user) do
    Phoenix.Component.assign(%Phoenix.LiveView.Socket{},
      consumer: "mattermost",
      current_user: user,
      rules: [],
      open: MapSet.new()
    )
  end

  defp globals, do: for(r <- Selection.list_rules(), r.instance_id == nil, do: r.selector)

  test "an unknown category is not written" do
    {:noreply, _} =
      SelectionTree.handle_event("toggle_category", %{"cat" => "bogus"}, socket(user!(true)))

    refute "bogus" in globals()
  end

  test "a group-scoped admin cannot toggle a global category" do
    {:noreply, _} =
      SelectionTree.handle_event(
        "toggle_category",
        %{"cat" => "availability"},
        socket(user!(false))
      )

    refute "availability" in globals()
  end

  test "a non-numeric instance id is ignored, not a crash" do
    assert {:noreply, _} =
             SelectionTree.handle_event(
               "toggle_service",
               %{"iid" => "x", "key" => "availability"},
               socket(user!(true))
             )

    assert {:noreply, _} =
             SelectionTree.handle_event("toggle_open", %{"iid" => "1;x"}, socket(user!(true)))
  end
end
