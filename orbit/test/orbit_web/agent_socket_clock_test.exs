defmodule OrbitWeb.AgentSocketClockTest do
  @moduledoc """
  A metrics push is stamped with the SERVER clock only. The agent's own `ts`
  must not move `agent_last_seen` / `last_success_at`: a clock running ahead
  would hide the agent's silence from the stale sweep for the skew, a clock
  running behind would make a live agent look silent and flip it offline.
  """
  use Orbit.DataCase, async: false

  alias OrbitWeb.AgentSocket

  setup do
    group =
      Repo.insert!(%Orbit.Accounts.Group{name: "clock-#{System.unique_integer([:positive])}"})

    {:ok, inst} =
      Orbit.Instances.create_instance(
        %{
          "name" => "clock-box-#{System.unique_integer([:positive])}",
          "device_type" => "proxmox",
          "transport" => "push"
        },
        group.id
      )

    {:ok, inst: inst}
  end

  for {name, skew_seconds} <- [
        {"agent clock a day ahead", 86_400},
        {"agent clock an hour behind", -3_600},
        {"agent clock in sync", 0}
      ] do
    test "#{name}: stamped at server time", %{inst: inst} do
      agent_ts =
        DateTime.utc_now() |> DateTime.add(unquote(skew_seconds)) |> DateTime.to_iso8601()

      before = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)

      push(inst, %{"ts" => agent_ts})

      after_ = NaiveDateTime.utc_now()
      {last_seen, last_success} = stamps(inst.id)

      for stamp <- [last_seen, last_success] do
        assert NaiveDateTime.compare(stamp, before) != :lt
        assert NaiveDateTime.compare(stamp, after_) != :gt
      end
    end
  end

  test "push without ts is stamped at server time", %{inst: inst} do
    before = NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
    push(inst, %{})
    {last_seen, _} = stamps(inst.id)
    assert NaiveDateTime.compare(last_seen, before) != :lt
  end

  defp push(inst, data) do
    state = %AgentSocket{instance_id: inst.id, instance_name: inst.name, hello_seen: true}
    frame = Jason.encode!(%{"type" => "metrics", "data" => data})
    assert {:ok, _} = AgentSocket.handle_in({frame, [opcode: :text]}, state)
  end

  defp stamps(id) do
    %{rows: [[seen, success]]} =
      Repo.query!("SELECT agent_last_seen, last_success_at FROM instances WHERE id = ?", [id])

    {seen, success}
  end
end
