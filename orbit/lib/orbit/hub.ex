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

  require Logger

  @default_timeout_ms 30_000

  defmodule Agent do
    @moduledoc false
    defstruct [
      :instance_id,
      :pid,
      :agent_version,
      :platform,
      :checkmk_sha256,
      :source_ip,
      :connected_at,
      :last_update_error,
      :last_update_version,
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

  @doc """
  In-memory hub counters + start time (stats.py /hub/stats parity). The
  numbers reset with the process — that is the point (live health, not
  history).
  """
  def stats(server \\ __MODULE__) do
    GenServer.call(server, :stats)
  end

  @doc "Bump one hub counter (auth_failures, json_errors, unknown_messages, …)."
  def bump(server \\ __MODULE__, key) when is_atom(key) do
    GenServer.cast(server, {:bump, key})
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

  @doc "Ingest a metrics push into the per-instance section cache (guarded writes)."
  def ingest_metrics(server \\ __MODULE__, instance_id, data) do
    GenServer.cast(server, {:ingest_metrics, instance_id, data})
  end

  @doc "The cached section entry for an instance (or empty map)."
  def cache_entry(server \\ __MODULE__, instance_id) do
    GenServer.call(server, {:cache_entry, instance_id})
  end

  @doc """
  Merge an operator-initiated firmware.check verdict into the cached
  firmware section (python hub.set_firmware parity), so all four check
  surfaces see the fresh verdict without waiting for the next push.
  """
  @spec set_firmware(GenServer.server(), integer(), map()) :: :ok
  def set_firmware(server \\ __MODULE__, instance_id, fields) when is_map(fields) do
    GenServer.cast(server, {:set_firmware, instance_id, fields})
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

  @doc """
  Pin a self-update outcome on the connected agent: a rejection stays visible
  in list_connected (the agent stays connected when it refuses); a success
  restarts the agent → fresh connection, clearing it (update.py:_push_update).
  """
  @spec pin_update_result(GenServer.server(), integer(), map(), String.t()) :: :ok
  def pin_update_result(server \\ __MODULE__, instance_id, result, version) do
    GenServer.cast(server, {:pin_update_result, instance_id, result, version})
  end

  ## Tunnel multiplex (GUI/shell/capture ride the one agent socket, §27.5) ----

  @doc """
  Open a tunnel stream to a connected agent. The calling process becomes the
  stream consumer: it receives `{:tunnel, stream, op, frame}` messages for
  every agent→hub frame on this stream, and must `close_tunnel/2` on exit.
  Returns `{:ok, stream}` or `{:error, :not_connected}`.

  `open_extra` carries the per-kind open fields (shell: rows/cols/kind;
  capture: interface/filter/kind; GUI-TCP: none).
  """
  @spec open_tunnel(GenServer.server(), integer(), map()) ::
          {:ok, String.t()} | {:error, :not_connected}
  def open_tunnel(server \\ __MODULE__, instance_id, open_extra) do
    GenServer.call(server, {:open_tunnel, instance_id, self(), open_extra})
  end

  @doc "Send raw bytes on a stream (base64-framed to the agent)."
  def tunnel_send(server \\ __MODULE__, stream, data) when is_binary(data) do
    GenServer.cast(server, {:tunnel_op, stream, "data", %{"data" => Base.encode64(data)}})
  end

  @doc "Resize a shell stream's PTY."
  def tunnel_resize(server \\ __MODULE__, stream, rows, cols) do
    GenServer.cast(server, {:tunnel_op, stream, "resize", %{"rows" => rows, "cols" => cols}})
  end

  @doc "Close a stream (tells the agent, drops the routing entry)."
  def close_tunnel(server \\ __MODULE__, stream) do
    GenServer.cast(server, {:close_tunnel, stream})
  end

  @doc "Route an inbound tunnel frame from the agent socket to its consumer."
  def deliver_tunnel(server \\ __MODULE__, frame) do
    GenServer.cast(server, {:deliver_tunnel, frame})
  end

  @roster_topic "hub:roster"

  @doc "PubSub topic notified (payload `:roster_changed`) on connect/disconnect."
  def roster_topic, do: @roster_topic

  # Roster edges (connect/disconnect) are broadcast so LiveViews react
  # immediately; per-push metric churn is NOT broadcast (too chatty) — live
  # views poll on a tier timer for the numbers, like the react refetchInterval.
  defp broadcast_roster_change do
    Phoenix.PubSub.broadcast(Orbit.PubSub, @roster_topic, :roster_changed)
  end

  @doc """
  Fire-and-forget a live config_update to a connected agent (push_interval,
  ipsec_ping_monitors, connectivity_monitors — §27.8). Best-effort: absent
  agent is a no-op (the value is re-sent in the welcome frame on reconnect).
  """
  @spec send_config(GenServer.server(), integer(), map()) :: :ok
  def send_config(server \\ __MODULE__, instance_id, fields) when is_map(fields) do
    GenServer.cast(server, {:send_config, instance_id, fields})
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok) do
    Process.flag(:trap_exit, false)

    # Rehydrate the section cache from the last persisted snapshot per
    # instance. Without it a restart leaves every box blank until its next
    # push — no checks, no status, and the exports report nothing for up to
    # a poll interval. The old python hub owned this column; that ended at
    # the 4.0.0 cutover, so orbit owns it now (the "until cutover" note in
    # cache.ex/transitions.ex is what this replaces).
    #
    # Never fatal: a boot that cannot read the column starts cold, exactly
    # as before. Gated by :write_metrics like the snapshot writer, so hub
    # unit tests (which have no instances table) start cold too.
    {:ok,
     %{
       agents: %{},
       pending: %{},
       cache: hydrate_cache(),
       streams: %{},
       ipsec_dup: %{},
       counters: %{},
       started_at: DateTime.utc_now()
     }}
  end

  defp hydrate_cache do
    if Application.get_env(:orbit, :write_metrics, true), do: read_snapshots(), else: %{}
  end

  defp read_snapshots do
    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT id, status_snapshot FROM instances " <>
          "WHERE deleted_at IS NULL AND status_snapshot IS NOT NULL"
      )

    cache =
      for [id, json] <- rows, into: %{} do
        case Jason.decode(to_string(json)) do
          {:ok, entry} when is_map(entry) -> {id, entry}
          _ -> {id, %{}}
        end
      end

    Logger.info("hub.cache_hydrated instances=#{map_size(cache)}")
    cache
  rescue
    error ->
      Logger.warning("hub.cache_hydrate_failed error=#{inspect(error)}")
      %{}
  end

  @impl true
  def handle_call(:stats, _from, state) do
    {:reply,
     %{
       counters: Map.get(state, :counters, %{}),
       started_at: Map.get(state, :started_at) || DateTime.utc_now(),
       push_p95_ms: percentile(Map.get(state, :push_times, []), 0.95),
       push_samples: length(Map.get(state, :push_times, []))
     }, state}
  end

  def handle_call({:register, instance_id, pid, meta}, _from, state) do
    state = bump_counter(state, :connects)

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
      source_ip: meta[:source_ip],
      connected_at: DateTime.utc_now()
    }

    broadcast_roster_change()
    {:reply, :ok, put_in(state.agents[instance_id], agent)}
  end

  def handle_call({:unregister, instance_id, pid}, _from, state) do
    case state.agents[instance_id] do
      %Agent{pid: ^pid} ->
        broadcast_roster_change()

        {:reply, :ok,
         %{bump_counter(state, :disconnects) | agents: Map.delete(state.agents, instance_id)}}

      _ ->
        {:reply, :stale, state}
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

  def handle_call({:cache_entry, instance_id}, _from, state) do
    {:reply, Orbit.Hub.Cache.entry(state.cache, instance_id), state}
  end

  def handle_call({:open_tunnel, instance_id, consumer, open_extra}, _from, state) do
    case state.agents[instance_id] do
      %Agent{pid: pid} ->
        stream = generate_request_id()
        ref = Process.monitor(consumer)

        frame =
          Map.merge(%{"type" => "tunnel", "op" => "open", "stream" => stream}, open_extra)

        send(pid, {:push_frame, frame})

        streams =
          Map.put(state.streams, stream, %{
            consumer: consumer,
            agent_pid: pid,
            monitor: ref,
            instance_id: instance_id
          })

        {:reply, {:ok, stream}, %{state | streams: streams}}

      nil ->
        {:reply, {:error, :not_connected}, state}
    end
  end

  @impl true
  def handle_cast({:resolve, request_id, result}, state) do
    case Map.pop(state.pending, request_id) do
      {nil, _} ->
        # Late result after timeout — python hub logs and drops likewise.
        {:noreply, state}

      {caller, pending} ->
        send(caller, {:command_result, request_id, result})
        {:noreply, %{bump_counter(state, :command_results) | pending: pending}}
    end
  end

  def handle_cast({:bump, key}, state) do
    {:noreply, bump_counter(state, key)}
  end

  def handle_cast({:record_push, instance_id}, state) do
    state = bump_counter(state, :pushes)

    {:noreply,
     update_agent(state, instance_id, fn a ->
       %{a | pushes: a.pushes + 1, last_push_at: DateTime.utc_now()}
     end)}
  end

  def handle_cast({:record_pong, instance_id}, state) do
    state = bump_counter(state, :pongs)
    {:noreply, update_agent(state, instance_id, fn a -> %{a | pongs: a.pongs + 1} end)}
  end

  def handle_cast({:pin_update_result, instance_id, result, version}, state) do
    {:noreply,
     update_agent(state, instance_id, fn a ->
       if result["success"] do
         %{a | last_update_error: nil, last_update_version: nil}
       else
         %{
           a
           | last_update_error: result["output"] || "update failed",
             last_update_version: version
         }
       end
     end)}
  end

  def handle_cast({:set_firmware, instance_id, fields}, state) do
    cache = Orbit.Hub.Cache.merge_section(state.cache, instance_id, "firmware", fields)
    {:noreply, %{state | cache: cache}}
  end

  def handle_cast({:ingest_metrics, instance_id, data}, state) do
    started = System.monotonic_time(:microsecond)
    now = DateTime.utc_now()
    # Duplicate-SA streak (hub.py _annotate_dup_persistence): annotate the
    # push BEFORE it hits the cache and the diff, so both see the debounced
    # phase2_dup_persistent flag. Diff runs against the PRE-ingest snapshot.
    # Map.get on the STATE too: a hot code reload leaves the running
    # GenServer with the pre-upgrade state map (no :ipsec_dup key yet).
    dup_state = Map.get(state, :ipsec_dup, %{})

    {data, dup_streaks} =
      Orbit.Ipsec.History.annotate_dup(data, Map.get(dup_state, instance_id, %{}))

    prev_ipsec = Orbit.Hub.Cache.entry(state.cache, instance_id)["ipsec"]

    # Linux nodes push one checkmk blob instead of per-section numbers —
    # expand it here, once, so the cache AND the metric-history writer below
    # see the same sections (expanding inside ingest left the series flat).
    {data, cpu_state} = Orbit.Hub.Cache.expand(state.cache, instance_id, data)
    cache = Orbit.Hub.Cache.ingest(state.cache, instance_id, data, now, cpu_state)
    maybe_persist_logfiles(instance_id, data)
    maybe_persist_config_backup(instance_id, data)
    maybe_persist_metrics(instance_id, now, data)
    maybe_persist_snapshot(instance_id, cache)
    maybe_persist_ipsec_events(instance_id, now, prev_ipsec, data)

    {:noreply,
     state
     |> Map.put(:cache, cache)
     |> Map.put(:ipsec_dup, Map.put(dup_state, instance_id, dup_streaks))
     |> record_push_duration(System.monotonic_time(:microsecond) - started)}
  end

  def handle_cast({:tunnel_op, stream, op, fields}, state) do
    case state.streams[stream] do
      %{agent_pid: pid} ->
        frame = Map.merge(%{"type" => "tunnel", "op" => op, "stream" => stream}, fields)
        send(pid, {:push_frame, frame})
        {:noreply, state}

      nil ->
        {:noreply, state}
    end
  end

  def handle_cast({:close_tunnel, stream}, state) do
    {:noreply, drop_stream(state, stream, tell_agent: true)}
  end

  def handle_cast({:deliver_tunnel, %{"stream" => stream} = frame}, state) do
    state = bump_counter(state, :tunnel_frames)

    case state.streams[stream] do
      %{consumer: consumer} ->
        op = frame["op"]
        send(consumer, {:tunnel, stream, op, frame})
        # An agent-side close ends the stream; drop routing without re-telling
        # the agent (it just told us).
        if op == "close" do
          {:noreply, drop_stream(state, stream, tell_agent: false)}
        else
          {:noreply, state}
        end

      nil ->
        {:noreply, state}
    end
  end

  def handle_cast({:deliver_tunnel, _frame}, state), do: {:noreply, state}

  def handle_cast({:send_config, instance_id, fields}, state) do
    case state.agents[instance_id] do
      %Agent{pid: pid} ->
        send(pid, {:push_frame, %{"type" => "config_update", "data" => fields}})
        {:noreply, state}

      nil ->
        {:noreply, state}
    end
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, consumer, _reason}, state) do
    # A tunnel consumer died — close its streams so the agent tears them down.
    streams =
      state.streams
      |> Enum.filter(fn {_s, meta} -> meta.consumer == consumer end)
      |> Enum.map(fn {s, _} -> s end)

    new_state = Enum.reduce(streams, state, &drop_stream(&2, &1, tell_agent: true))
    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp drop_stream(state, stream, tell_agent: tell_agent) do
    case Map.pop(state.streams, stream) do
      {nil, _} ->
        state

      {meta, rest} ->
        Process.demonitor(meta.monitor, [:flush])

        if tell_agent do
          frame = %{"type" => "tunnel", "op" => "close", "stream" => stream}
          send(meta.agent_pid, {:push_frame, frame})
        end

        %{state | streams: rest}
    end
  end

  defp update_agent(state, instance_id, fun) do
    case state.agents[instance_id] do
      nil -> state
      agent -> put_in(state.agents[instance_id], fun.(agent))
    end
  end

  # Rolling window of hub-side push processing times (µs). Bounded so the
  # hub never grows memory on a busy fleet; @slow_push_us is what the
  # "Slow pushes" counter counts, so a degrading hub shows up as a number
  # rather than as "the dashboard feels laggy".
  @push_window 500
  @slow_push_us 250_000

  defp record_push_duration(state, micros) do
    window = [micros | Map.get(state, :push_times, [])] |> Enum.take(@push_window)
    state = Map.put(state, :push_times, window)

    if micros >= @slow_push_us, do: bump_counter(state, :slow_pushes), else: state
  end

  @doc false
  def percentile([], _p), do: nil

  def percentile(values, p) do
    sorted = Enum.sort(values)
    idx = min(round(p * length(sorted)) - 1, length(sorted) - 1) |> max(0)
    Enum.at(sorted, idx) |> Kernel./(1000) |> Float.round(1)
  end

  # Hot-reload-safe: the running state map may predate the :counters key.
  defp bump_counter(state, key) do
    counters = Map.get(state, :counters, %{})
    Map.put(state, :counters, Map.update(counters, key, 1, &(&1 + 1)))
  end

  defp generate_request_id do
    Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
  end

  # Logfile persistence + event extraction is CPU work (regex-walks up to ~1 MB)
  # and DB I/O — never do it in the hub loop. Fire-and-forget off the GenServer,
  # mirroring the python enqueue; a failed persist must not drop the metrics push.
  defp maybe_persist_logfiles(instance_id, %{"logfiles" => logfiles})
       when is_list(logfiles) and logfiles != [] do
    Task.start(fn -> Orbit.Logs.Store.ingest(instance_id, logfiles) end)
  end

  defp maybe_persist_logfiles(_instance_id, _data), do: :ok

  # Config-backup decode (gunzip) + Fernet-encrypt is CPU work; persist off the
  # hub loop, fire-and-forget, like the logfiles path.
  defp maybe_persist_config_backup(instance_id, %{"config_backup" => payload})
       when is_map(payload) and payload != %{} do
    Task.start(fn -> Orbit.ConfigBackup.Store.record(instance_id, payload) end)
  end

  defp maybe_persist_config_backup(_instance_id, _data), do: :ok

  # Persist the just-updated cache entry so a restart can rehydrate it
  # (python hub parity: it wrote status_snapshot in the same push handler).
  # Fire-and-forget off the hub loop, and disabled in test like the metrics
  # writer — hub unit tests have no instances table.
  defp maybe_persist_snapshot(instance_id, cache) do
    if Application.get_env(:orbit, :write_metrics, true) do
      entry = Map.get(cache, instance_id, %{})

      Task.start(fn ->
        Orbit.Repo.query!(
          "UPDATE instances SET status_snapshot = ? WHERE id = ?",
          [Jason.encode!(entry), instance_id]
        )
      end)
    end
  end

  # Metric history rows ride every ingest (agent push AND poller bridge —
  # write_poll_metrics parity; without this the charts flatline after
  # cutover). DB I/O off the hub loop, fire-and-forget like the logfiles
  # path. Off in test (:write_metrics) — hub unit tests have no metrics
  # table and must not race the sandbox.
  defp maybe_persist_metrics(instance_id, now, data) do
    if Application.get_env(:orbit, :write_metrics, true) do
      Task.start(fn -> Orbit.Metrics.write_push(instance_id, now, data) end)
    end
  end

  # IPsec state transitions feed the tunnel-history dialog. Diffed against
  # the pre-ingest cache; an empty/absent ipsec section in the push is a
  # collector failure and never diffs (truthy-guard semantics, same as the
  # cache). Shares the :write_metrics test gate — same table-less test DB.
  defp maybe_persist_ipsec_events(instance_id, now, prev_ipsec, data) do
    with true <- Application.get_env(:orbit, :write_metrics, true),
         %{"tunnels" => prev_tunnels} <- prev_ipsec,
         %{"tunnels" => new_tunnels} when new_tunnels != [] <- data["ipsec"] do
      case Orbit.Ipsec.History.diff(prev_tunnels, new_tunnels) do
        [] -> :ok
        events -> Task.start(fn -> Orbit.Ipsec.History.record(instance_id, now, events) end)
      end
    else
      _ -> :ok
    end
  end
end
