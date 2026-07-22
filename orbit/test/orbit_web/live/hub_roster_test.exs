defmodule OrbitWeb.HubRosterTest do
  @moduledoc """
  Scope gate over the unscoped hub roster (invariant 5), now batched: one
  visible-instance map instead of a per-agent Scope.get_instance (an N+1
  that fired ~70 sequential queries per /hub load on the prod fleet). The
  security property must survive the batching: an agent whose instance is
  not in the caller's visible set is dropped, never rendered.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.HubStatusLive

  defp agent(id) do
    %{
      instance_id: id,
      agent_version: "4.2.12",
      platform: "opnsense",
      pushes: 5,
      connected_at: nil,
      last_push_at: nil,
      last_update_error: nil
    }
  end

  defp inst(name) do
    %{name: name, shell_enabled: false, base_url: ""}
  end

  defp no_cpu(_id), do: nil
  defp closed(_inst), do: false

  test "an agent outside the visible set is dropped, never rendered" do
    rows =
      HubStatusLive.roster([agent(1), agent(2)], %{1 => inst("opn1")}, &no_cpu/1, &closed/1)

    assert [%{instance_id: 1, instance_name: "opn1"}] =
             Enum.map(rows, &Map.take(&1, [:instance_id, :instance_name]))
  end

  test "an empty visible set renders nothing (zero-groups user semantics)" do
    assert HubStatusLive.roster([agent(1)], %{}, &no_cpu/1, &closed/1) == []
  end

  test "rows sort by instance name and carry the injected decorations" do
    visible = %{1 => inst("bravo"), 2 => inst("alpha")}

    rows =
      HubStatusLive.roster([agent(1), agent(2)], visible, fn id -> id * 10.0 end, fn _ ->
        true
      end)

    assert Enum.map(rows, & &1.instance_name) == ["alpha", "bravo"]
    assert Enum.map(rows, & &1.cpu) == [20.0, 10.0]
    assert Enum.all?(rows, & &1.gui_openable)
  end
end
