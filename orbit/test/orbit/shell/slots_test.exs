defmodule Orbit.Shell.SlotsTest do
  use ExUnit.Case, async: true

  alias Orbit.Shell.Slots

  setup do
    slots = start_supervised!({Slots, name: nil})
    %{slots: slots}
  end

  # Each acquire is attributed to a distinct holder process so the cap logic
  # is exercised the way real sockets use it (one process per session).
  defp acquire_in_new_process(slots, user_id, instance_id) do
    parent = self()

    pid =
      spawn(fn ->
        result = Slots.acquire(slots, user_id, instance_id)
        send(parent, {:acquired, self(), result})
        receive do: (:die -> :ok)
      end)

    receive do
      {:acquired, ^pid, result} -> {pid, result}
    end
  end

  test "caps at 5 per user", %{slots: slots} do
    pids =
      for _ <- 1..5 do
        {pid, :ok} = acquire_in_new_process(slots, 1, %{} |> :erlang.phash2())
        pid
      end

    assert {_pid, {:error, :cap}} = acquire_in_new_process(slots, 1, 999)
    assert length(pids) == 5
  end

  test "caps at 5 per instance across different users", %{slots: slots} do
    for u <- 1..5 do
      {_pid, :ok} = acquire_in_new_process(slots, u, 42)
    end

    assert {_pid, {:error, :cap}} = acquire_in_new_process(slots, 6, 42)
  end

  test "a died holder frees its slot", %{slots: slots} do
    {pid, :ok} = acquire_in_new_process(slots, 1, 42)
    for _ <- 1..4, do: acquire_in_new_process(slots, 1, 42)
    assert {_p, {:error, :cap}} = acquire_in_new_process(slots, 1, 42)

    send(pid, :die)
    # Give the DOWN message time to land.
    Process.sleep(30)
    assert {_p, :ok} = acquire_in_new_process(slots, 1, 42)
  end

  test "independent user/instance combos don't interfere", %{slots: slots} do
    assert {_p, :ok} = acquire_in_new_process(slots, 1, 10)
    assert {_p, :ok} = acquire_in_new_process(slots, 2, 20)
  end
end
