defmodule OrbitWeb.IpsecIdsInputTest do
  @moduledoc """
  IPsec tunnel ids / SA unique ids come from DOM attributes and become
  `swanctl` argv on the box (agent, root) or part of the SSH diagnose script
  (Securepoint). Strict format server-side; the Diagnose button is write-gated
  in the UI, so the handler is too.
  """
  use ExUnit.Case, async: true

  alias Orbit.Instances.Instance
  alias OrbitWeb.InstanceDetailLive, as: Detail
  alias OrbitWeb.VpnLive

  describe "Orbit.Ipsec.Ids" do
    test "tunnel ids: swanctl/Securepoint names pass, option-like and shell-ish fail" do
      for ok <- ["con1", "0f4d3c2a-1b2c-4d5e-8f90-a1b2c3d4e5f6", "OCV$20MEH", "a.b_c:1"],
          do: assert(Orbit.Ipsec.Ids.tunnel_id?(ok), ok)

      for bad <- ["-x", "--uri=x", "a b", "a;b", "a'b", "", nil, %{}, String.duplicate("a", 129)],
          do: refute(Orbit.Ipsec.Ids.tunnel_id?(bad), inspect(bad))
    end

    test "unique ids are digits or blank" do
      assert Orbit.Ipsec.Ids.unique_id?("")
      assert Orbit.Ipsec.Ids.unique_id?("42")
      refute Orbit.Ipsec.Ids.unique_id?("-1")
      refute Orbit.Ipsec.Ids.unique_id?("1 2")
      refute Orbit.Ipsec.Ids.unique_id?(%{})
    end
  end

  defp detail_socket(over) do
    Phoenix.Component.assign(
      %Phoenix.LiveView.Socket{},
      Map.merge(
        %{
          instance: %Instance{id: 1, transport: "push"},
          current_user: %{id: 1, role: "admin", groups: []},
          writable: true,
          ipsec_busy: MapSet.new(),
          ipsec_msg: nil,
          diagnosis_busy: nil
        },
        over
      )
    )
  end

  test "connect/disconnect/reconnect with a bad id or uid start nothing" do
    for {kind, params} <- [
          {"ipsec_connect", %{"id" => "-x"}},
          {"ipsec_disconnect", %{"id" => "con1", "uid" => "1;reboot"}},
          {"ipsec_reconnect", %{"id" => "con 1", "uid" => ""}}
        ] do
      {:noreply, s} = Detail.handle_event(kind, params, detail_socket(%{}))
      assert MapSet.size(s.assigns.ipsec_busy) == 0, kind
      assert {:error, _} = s.assigns.ipsec_msg
    end
  end

  test "diagnose is refused for a read-only session and for a bad id" do
    {:noreply, s} =
      Detail.handle_event("ipsec_diagnose", %{"id" => "con1"}, detail_socket(%{writable: false}))

    assert s.assigns.diagnosis_busy == nil

    {:noreply, s} = Detail.handle_event("ipsec_diagnose", %{"id" => "a;b"}, detail_socket(%{}))
    assert s.assigns.diagnosis_busy == nil
  end

  test "fleet reconnect refuses a bad id before the scope lookup" do
    socket =
      Phoenix.Component.assign(%Phoenix.LiveView.Socket{},
        current_user: %{id: 1, role: "admin", groups: []},
        writable: true,
        busy: MapSet.new(),
        msg: nil
      )

    {:noreply, s} =
      VpnLive.handle_event("reconnect", %{"iid" => "1", "id" => "--x", "uid" => ""}, socket)

    assert MapSet.size(s.assigns.busy) == 0
  end
end
