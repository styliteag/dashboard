defmodule Orbit.Hub do
  @moduledoc """
  In-memory registry of connected agents + command dispatch — port of
  backend/src/app/agent_hub/hub.py for the wire protocol pinned in
  docs/agent-architecture.md §27.

  One GenServer owns the registry map; the per-connection WebSock processes
  (OrbitWeb.AgentSocket) do the socket I/O. Commands are futures: the caller
  blocks in `send_command/4` (GenServer.call with the request timeout), the
  socket resolves it via `resolve_command/2` when the matching
  `command_result` arrives — python-parity timeout answer
  `{"success": false, "output": "command timed out"}`.

  Duplicate connects are last-writer-wins: registering an instance closes
  the previous socket. Unregister is identity-aware (pid must match) so a
  dying old connection never evicts its replacement (hub.py:275 parity).
  """

  use GenServer

  @default_timeout_ms 30_000

  defmodule Agent do
    @moduledoc false
    defstruct [
      :instance_id,
      :pid,
      :agent_version,
      :platform,
      :checkmk_sha256,
      :connected_at,
      pushes: 0,
      pongs: 0,
      last_push_at: nil
    ]
  end

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Register the calling socket process for an instance (last-writer-wins)."
  def register(server \\ __MODULE__, instance_id, meta) do
    GenServer.call(server, {:register, instance_id, self(), meta})
  end

  @doc "Identity-aware unregister: only removes the entry if it still points at pid."
  def unregister(server \\ __MODULE__, instance_id) do
    GenServer.call(server, {:unregister, instance_id, self()})
  end

  @doc "Connected agent metadata (or nil)."
  def get(server \\ __MODULE__, instance_id) do
    GenServer.call(server, {:get, instance_id})
  end

  def list_connected(server \\ __MODULE__) do
    GenServer.call(server, :list_connected)
  end

  @doc "Record a metrics push (counters; DB stamping happens in the socket)."
  def record_push(server \\ __MODULE__, instance_id) do
    GenServer.cast(server, {:record_push, instance_id})
  end

  def record_pong(server \\ __MODULE__, instance_id) do
    GenServer.cast(server, {:record_pong, instance_id})
  end

  @doc """
  Send a command to a connected agent and await its result.

  Returns the agent's `result` map, `{:error, :not_connected}`, or the
  python-parity timeout map. Blocks the caller up to `timeout_ms`.
  """
  @spec send_command(integer(), String.t(), map(), pos_integer()) ::
          map() | {:error, :not_connected}
  def send_command(instance_id, action, params, timeout_ms \\ @default_timeout_ms)
      when is_integer(instance_id) do
    # No double-default head: a 4-arg call once bound server=instance_id and
    # crashed in GenServer.whereis(7). Server override is its own function.
    send_command_on(__MODULE__, instance_id, action, params, timeout_ms)
  end

  @spec send_command_on(GenServer.server(), integer(), String.t(), map(), pos_integer()) ::
          map() | {:error, :not_connected}
  def send_command_on(server, instance_id, action, params, timeout_ms) do
    request_id = generate_request_id()

    case GenServer.call(server, {:dispatch, instance_id, request_id, action, params}) do
      :ok ->
        receive do
          {:command_result, ^request_id, result} -> result
        after
          timeout_ms ->
            GenServer.call(server, {:drop_pending, request_id})
            %{"success" => false, "output" => "command timed out"}
        end

      {:error, :not_connected} = err ->
        err
    end
  end

  @doc "Resolve a pending command future (called by the socket on command_result)."
  def resolve_command(server \\ __MODULE__, request_id, result) do
    GenServer.cast(server, {:resolve, request_id, result})
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok) do
    {:ok, %{agents: %{}, pending: %{}}}
  end

  @impl true
  def handle_call({:register, instance_id, pid, meta}, _from, state) do
    case state.agents[instance_id] do
      %Agent{pid: old_pid} when old_pid != pid ->
        # Last-writer-wins: tell the old socket to close (4000-range close is
        # the socket's business; python hub just closes the old ws).
        send(old_pid, :hub_replaced)

      _ ->
        :ok
    end

    agent = %Agent{
      instance_id: instance_id,
      pid: pid,
      agent_version: meta[:agent_version],
      platform: meta[:platform],
      checkmk_sha256: meta[:checkmk_sha256],
      connected_at: DateTime.utc_now()
    }

    {:reply, :ok, put_in(state.agents[instance_id], agent)}
  end

  def handle_call({:unregister, instance_id, pid}, _from, state) do
    case state.agents[instance_id] do
      %Agent{pid: ^pid} -> {:reply, :ok, %{state | agents: Map.delete(state.agents, instance_id)}}
      _ -> {:reply, :stale, state}
    end
  end

  def handle_call({:get, instance_id}, _from, state) do
    {:reply, state.agents[instance_id], state}
  end

  def handle_call(:list_connected, _from, state) do
    {:reply, Map.values(state.agents), state}
  end

  def handle_call({:dispatch, instance_id, request_id, action, params}, {caller, _tag}, state) do
    case state.agents[instance_id] do
      %Agent{pid: pid} ->
        frame = %{
          "type" => "command",
          "request_id" => request_id,
          "action" => action,
          "params" => params
        }

        send(pid, {:push_frame, frame})
        {:reply, :ok, put_in(state.pending[request_id], caller)}

      nil ->
        {:reply, {:error, :not_connected}, state}
    end
  end

  def handle_call({:drop_pending, request_id}, _from, state) do
    {:reply, :ok, %{state | pending: Map.delete(state.pending, request_id)}}
  end

  @impl true
  def handle_cast({:resolve, request_id, result}, state) do
    case Map.pop(state.pending, request_id) do
      {nil, _} ->
        # Late result after timeout — python hub logs and drops likewise.
        {:noreply, state}

      {caller, pending} ->
        send(caller, {:command_result, request_id, result})
        {:noreply, %{state | pending: pending}}
    end
  end

  def handle_cast({:record_push, instance_id}, state) do
    {:noreply,
     update_agent(state, instance_id, fn a ->
       %{a | pushes: a.pushes + 1, last_push_at: DateTime.utc_now()}
     end)}
  end

  def handle_cast({:record_pong, instance_id}, state) do
    {:noreply, update_agent(state, instance_id, fn a -> %{a | pongs: a.pongs + 1} end)}
  end

  defp update_agent(state, instance_id, fun) do
    case state.agents[instance_id] do
      nil -> state
      agent -> put_in(state.agents[instance_id], fun.(agent))
    end
  end

  defp generate_request_id do
    Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
  end
end
