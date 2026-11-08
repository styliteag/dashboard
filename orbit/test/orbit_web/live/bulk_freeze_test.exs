defmodule OrbitWeb.BulkFreezeTest do
  @moduledoc """
  Bulk actions run on exactly the boxes the confirmation dialog named: the
  target ids are frozen at bulk_ask. A selection changed between dialog and
  submit (a crafted toggle_select, a live re-render) can drop boxes, never
  add unconfirmed ones; ids outside the visible fleet are never confirmed.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.{FirmwareLive, InstancesLive}

  test "instances: bulk_ask freezes the visible selected ids with their names" do
    socket =
      Phoenix.Component.assign(%Phoenix.LiveView.Socket{},
        writable: true,
        bulk_busy: false,
        selected: MapSet.new([1, 2, 99]),
        instances: [%{id: 1, name: "a"}, %{id: 2, name: "b"}, %{id: 3, name: "c"}],
        confirm: nil,
        confirm_typed: ""
      )

    {:noreply, s} = InstancesLive.handle_event("bulk_ask", %{"action" => "reboot"}, socket)
    assert s.assigns.confirm.ids == [1, 2]
    assert s.assigns.confirm.names == ["a", "b"]
  end

  test "firmware: the run set is the confirmed set, minus rows no longer eligible" do
    row = fn id, eligible? -> %{id: id, upgrade_available: eligible?, firmware_locked: false} end
    confirm = %{action: "firmware_update", ids: [1, 2]}
    rows = [row.(1, true), row.(2, false), row.(3, true)]
    assert FirmwareLive.frozen_targets(confirm, rows, MapSet.new([1, 2, 3])) == [1]
  end
end
