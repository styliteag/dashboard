defmodule Orbit.Ipsec.HistoryTest do
  @moduledoc "Tunnel transition diff (ipsec/history.py parity) on raw agent maps."
  use ExUnit.Case, async: true

  alias Orbit.Ipsec.History

  defp tunnel(attrs) do
    Map.merge(
      %{
        "id" => "con1",
        "status" => "established",
        "phase2_up" => 1,
        "phase2_total" => 1,
        "children" => []
      },
      attrs
    )
  end

  test "phase1 up/down flips produce phase1_up / phase1_down" do
    assert [%{event_type: "phase1_down", old_value: "established", new_value: "down"}] =
             History.diff([tunnel(%{})], [tunnel(%{"status" => "down"})])

    assert [%{event_type: "phase1_up"}] =
             History.diff([tunnel(%{"status" => "down"})], [tunnel(%{})])
  end

  test "same up-ness but different wording is phase1_changed" do
    assert [%{event_type: "phase1_changed"}] =
             History.diff([tunnel(%{"status" => "established"})], [
               tunnel(%{"status" => "installed"})
             ])
  end

  test "phase2 count changes produce phase2_changed with x/n values" do
    assert [%{event_type: "phase2_changed", old_value: "1/1", new_value: "0/1"}] =
             History.diff([tunnel(%{})], [tunnel(%{"phase2_up" => 0})])
  end

  test "ping transitions: ok/fail recorded, none and unchanged skipped" do
    child = fn state ->
      [
        %{
          "name" => "c1",
          "local_ts" => "10.0.0.0/24",
          "remote_ts" => "10.1.0.0/24",
          "ping_state" => state
        }
      ]
    end

    assert [%{event_type: "ping_fail", child_name: "c1"}] =
             History.diff(
               [tunnel(%{"children" => child.("ok")})],
               [tunnel(%{"children" => child.("fail")})]
             )

    assert [] =
             History.diff(
               [tunnel(%{"children" => child.("ok")})],
               [tunnel(%{"children" => child.("none")})]
             )

    assert [] =
             History.diff(
               [tunnel(%{"children" => child.("ok")})],
               [tunnel(%{"children" => child.("ok")})]
             )
  end

  test "unknown tunnels and nil baselines never diff" do
    assert History.diff(nil, [tunnel(%{})]) == []
    assert History.diff([tunnel(%{"id" => "other"})], [tunnel(%{"status" => "down"})]) == []
  end

  test "record is a no-op on an empty diff" do
    assert History.record(1, DateTime.utc_now(), []) == 0
  end
end
