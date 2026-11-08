defmodule OrbitWeb.EventIdParseTest do
  @moduledoc """
  Ids in LiveView event params are client-controlled strings. A non-numeric
  id is a no-op, never a crash (a crash remounts the page and drops the
  user's state). Audit-log filters are type-guarded and the "more" window
  is capped.
  """
  use ExUnit.Case, async: true

  defp socket(assigns), do: Phoenix.Component.assign(%Phoenix.LiveView.Socket{}, assigns)

  test "OrbitWeb.ParamId.parse/1" do
    assert OrbitWeb.ParamId.parse("42") == 42
    assert OrbitWeb.ParamId.parse(" 42") == nil
    assert OrbitWeb.ParamId.parse("4x") == nil
    assert OrbitWeb.ParamId.parse(%{}) == nil
    assert OrbitWeb.ParamId.parse(nil) == nil
  end

  test "users / groups / log events / fleet selection ignore a bad id" do
    assert {:noreply, _} =
             OrbitWeb.UsersLive.handle_event("edit", %{"id" => "x"}, socket(editing: nil))

    assert {:noreply, _} =
             OrbitWeb.GroupsLive.handle_event(
               "rename_toggle",
               %{"group_id" => "x"},
               socket(renaming: nil)
             )

    assert {:noreply, _} =
             OrbitWeb.LogEventsLive.handle_event(
               "toggle_sample",
               %{"id" => "x"},
               socket(current_user: %{role: "admin"}, open_sample: nil)
             )

    assert {:noreply, _} =
             OrbitWeb.InstancesLive.handle_event(
               "toggle_select",
               %{"id" => "x"},
               socket(selected: MapSet.new())
             )

    assert {:noreply, _} =
             OrbitWeb.FirmwareLive.handle_event(
               "toggle_select",
               %{"id" => "x"},
               socket(selected: MapSet.new())
             )
  end

  test "audit: unknown type is ignored, the row window is capped" do
    s = socket(types: MapSet.new([:auth]), action_limit: 4_900)

    assert {:noreply, s2} =
             OrbitWeb.AuditLive.handle_event("toggle_type", %{"type" => "erlang"}, s)

    assert s2.assigns.types == MapSet.new([:auth])
    assert OrbitWeb.AuditLive.next_limit(4_900) == 5_000
    assert OrbitWeb.AuditLive.next_limit(5_000) == 5_000
  end
end
