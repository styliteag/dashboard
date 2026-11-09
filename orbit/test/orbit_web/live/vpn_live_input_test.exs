defmodule OrbitWeb.VpnLiveInputTest do
  @moduledoc """
  The VPN page's Phase-2 "Test" button sends `ipsec.ping_test` straight to
  the agent (it bypasses `Monitors.ping_test/4`). The same target checks
  apply: an option-like destination never leaves the dashboard.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.VpnLive

  defp socket(editor) do
    Phoenix.Component.assign(%Phoenix.LiveView.Socket{},
      current_user: %{id: 1, role: "superadmin", groups: []},
      writable: true,
      ping_test_busy: false,
      ping_test: nil,
      ping_editor: editor
    )
  end

  defp editor(over),
    do:
      Map.merge(
        %{instance_id: 1, source: "", destination: "10.0.0.1", ping_count: 3},
        over
      )

  test "an option-like destination is refused before any lookup or send" do
    {:noreply, s} = VpnLive.handle_event("p2mon_test", %{}, socket(editor(%{destination: "-f"})))
    assert {:error, msg} = s.assigns.ping_test
    assert msg =~ "destination"
    refute s.assigns.ping_test_busy
  end

  test "an option-like source is refused" do
    {:noreply, s} = VpnLive.handle_event("p2mon_test", %{}, socket(editor(%{source: "-I x"})))
    assert {:error, msg} = s.assigns.ping_test
    assert msg =~ "source"
  end
end
