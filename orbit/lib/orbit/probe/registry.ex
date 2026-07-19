defmodule Orbit.Probe.Registry do
  @moduledoc """
  Last probe result per instance — port of the deleted `probe/registry.py`.

  In-memory only, like the hub cache: a probe is a live measurement and a stale
  one is worthless, so nothing is persisted and a restart simply means "not
  measured yet" until the next run. Reads never block on a probe.

  Process-local, single node — same assumption the rest of the app makes.
  """

  use GenServer

  alias Orbit.Probe

  @name __MODULE__

  def start_link(opts),
    do: GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, @name))

  @doc "Latest result for an instance, or nil when it has never been probed."
  @spec get(integer()) :: Probe.result() | nil
  def get(instance_id) do
    case :ets.lookup(@name, instance_id) do
      [{^instance_id, result}] -> result
      [] -> nil
    end
  rescue
    ArgumentError -> nil
  end

  @doc "Store a result."
  def put(instance_id, result), do: GenServer.cast(@name, {:put, instance_id, result})

  @doc "Drop instances that no longer exist so the table cannot grow forever."
  def retain(instance_ids), do: GenServer.cast(@name, {:retain, MapSet.new(instance_ids)})

  @impl true
  def init(:ok) do
    :ets.new(@name, [:named_table, :set, :protected, read_concurrency: true])
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:put, id, result}, state) do
    :ets.insert(@name, {id, result})
    {:noreply, state}
  end

  def handle_cast({:retain, keep}, state) do
    for {id, _} <- :ets.tab2list(@name), not MapSet.member?(keep, id), do: :ets.delete(@name, id)
    {:noreply, state}
  end
end
