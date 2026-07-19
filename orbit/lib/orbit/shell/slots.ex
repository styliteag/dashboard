defmodule Orbit.Shell.Slots do
  @moduledoc """
  Concurrency caps for the interactive shell — mirror of ws.py
  `_shell_slot_acquire`: at most 5 sessions per user AND 5 per instance
  (close code 4008 when exceeded).

  A GenServer holding two counter maps. The caller passes its own pid;
  slots free automatically when that process dies (monitored), so a crashed
  browser tab never leaks a slot.
  """

  use GenServer

  @max_per_user 5
  @max_per_instance 5

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Acquire a shell slot for (user, instance). Returns :ok or {:error, :cap}."
  @spec acquire(GenServer.server(), integer(), integer()) :: :ok | {:error, :cap}
  def acquire(server \\ __MODULE__, user_id, instance_id) do
    GenServer.call(server, {:acquire, user_id, instance_id, self()})
  end

  @impl true
  def init(:ok), do: {:ok, %{by_user: %{}, by_instance: %{}, holders: %{}}}

  @impl true
  def handle_call({:acquire, user_id, instance_id, pid}, _from, state) do
    user_n = Map.get(state.by_user, user_id, 0)
    inst_n = Map.get(state.by_instance, instance_id, 0)

    if user_n >= @max_per_user or inst_n >= @max_per_instance do
      {:reply, {:error, :cap}, state}
    else
      ref = Process.monitor(pid)

      state = %{
        state
        | by_user: Map.update(state.by_user, user_id, 1, &(&1 + 1)),
          by_instance: Map.update(state.by_instance, instance_id, 1, &(&1 + 1)),
          holders: Map.put(state.holders, ref, {user_id, instance_id})
      }

      {:reply, :ok, state}
    end
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.holders, ref) do
      {nil, _} ->
        {:noreply, state}

      {{user_id, instance_id}, holders} ->
        {:noreply,
         %{
           state
           | by_user: dec(state.by_user, user_id),
             by_instance: dec(state.by_instance, instance_id),
             holders: holders
         }}
    end
  end

  defp dec(map, key) do
    case Map.get(map, key, 0) do
      n when n <= 1 -> Map.delete(map, key)
      n -> Map.put(map, key, n - 1)
    end
  end
end
