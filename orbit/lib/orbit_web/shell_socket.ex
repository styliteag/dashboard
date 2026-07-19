defmodule OrbitWeb.ShellSocket do
  @moduledoc """
  Browser side of the interactive terminal (xterm.js ⇄ root PTY on the box),
  §27.5 shell kind. This process is the tunnel consumer: it opens a
  `kind:"shell"` stream on the agent socket via the hub, forwards keystrokes
  as tunnel data, PTY output back to the browser, and translates resize.

  All authorization (origin, session, write role, scope, feature gate,
  per-instance opt-in, slot cap) happened in the controller BEFORE the
  upgrade; a failure arrives here as `{:auth_error, code}` and closes with
  that code so the frontend maps it to readable text.

  Frame shapes to the browser: PTY bytes are sent as binary WS frames;
  control messages (`{"type":"ping"}`) are JSON text. From the browser we
  accept binary (keystrokes) and JSON text `{"type":"resize",...}`.
  """

  @behaviour WebSock

  alias Orbit.Hub

  @ping_interval_ms 25_000

  # transport: :agent (tunnel via the hub) or :ssh (direct PTY, Securepoint).
  defstruct [:instance_id, :stream, :transport, :ssh_conn, :ssh_chan]

  @impl true
  def init(%{auth_error: code}) do
    {:stop, :normal, {code, "unauthorized"}, %__MODULE__{}}
  end

  def init(%{instance_id: instance_id, user_id: user_id} = arg) do
    transport = Map.get(arg, :transport, :agent)
    # Slot cap is the last gate (4008). Acquired here so it binds to THIS
    # socket process — Shell.Slots monitors us, freeing the slot when the
    # tab closes or crashes. A later open_tunnel failure stops the process,
    # which also frees the slot.
    case Orbit.Shell.Slots.acquire(user_id, instance_id) do
      {:error, :cap} ->
        {:stop, :normal, {4008, "too many sessions"}, %__MODULE__{}}

      :ok ->
        open(transport, instance_id)
    end
  end

  defp open(:agent, instance_id) do
    case Hub.open_tunnel(instance_id, %{"kind" => "shell", "rows" => 24, "cols" => 80}) do
      {:ok, stream} ->
        schedule_ping()
        {:ok, %__MODULE__{instance_id: instance_id, stream: stream, transport: :agent}}

      {:error, :not_connected} ->
        # Agent dropped between the controller check and the upgrade.
        {:stop, :normal, {4404, "agent not connected"}, %__MODULE__{}}
    end
  end

  # Securepoint: no agent to attach to, so the PTY comes straight over SSH. The
  # channel is opened from THIS process so :ssh delivers its output here.
  defp open(:ssh, instance_id) do
    with %Orbit.Instances.Instance{} = inst <-
           Orbit.Repo.get(Orbit.Instances.Instance, instance_id),
         {:ok, cfg} <- Orbit.Securepoint.SSH.config_for(inst),
         {:ok, conn, chan} <- Orbit.Securepoint.SSH.open_interactive(cfg, 24, 80) do
      schedule_ping()

      {:ok,
       %__MODULE__{instance_id: instance_id, transport: :ssh, ssh_conn: conn, ssh_chan: chan}}
    else
      _ -> {:stop, :normal, {4404, "ssh shell unavailable"}, %__MODULE__{}}
    end
  end

  @impl true
  def handle_in({data, [opcode: :binary]}, %{transport: :ssh} = state) do
    Orbit.Securepoint.SSH.send_data(state.ssh_conn, state.ssh_chan, data)
    {:ok, state}
  end

  def handle_in({data, [opcode: :binary]}, state) do
    # Keystrokes → tunnel data to the agent PTY.
    Hub.tunnel_send(state.stream, data)
    {:ok, state}
  end

  def handle_in({text, [opcode: :text]}, state) do
    case Jason.decode(text) do
      {:ok, %{"type" => "resize", "rows" => rows, "cols" => cols}} ->
        case state.transport do
          :ssh -> Orbit.Securepoint.SSH.resize(state.ssh_conn, state.ssh_chan, rows, cols)
          _ -> Hub.tunnel_resize(state.stream, rows, cols)
        end

        {:ok, state}

      _ ->
        {:ok, state}
    end
  end

  @impl true
  # SSH PTY output → binary frame to the browser. type 0 is stdout, 1 stderr;
  # a terminal wants both interleaved exactly as the box wrote them.
  def handle_info(
        {:ssh_cm, conn, {:data, chan, _type, bytes}},
        %{ssh_conn: conn, ssh_chan: chan} = state
      ) do
    {:push, {:binary, bytes}, state}
  end

  def handle_info({:ssh_cm, conn, {:closed, chan}}, %{ssh_conn: conn, ssh_chan: chan} = state) do
    {:stop, :normal, {1000, "shell closed"}, state}
  end

  def handle_info({:ssh_cm, conn, {:eof, chan}}, %{ssh_conn: conn, ssh_chan: chan} = state) do
    {:ok, state}
  end

  def handle_info({:ssh_cm, conn, _other}, %{ssh_conn: conn} = state), do: {:ok, state}

  # Agent PTY output → binary frame to the browser.
  def handle_info({:tunnel, _stream, "data", frame}, state) do
    case Base.decode64(frame["data"] || "") do
      {:ok, bytes} -> {:push, {:binary, bytes}, state}
      :error -> {:ok, state}
    end
  end

  # Agent closed the PTY (shell exited) → close the browser socket.
  def handle_info({:tunnel, _stream, "close", _frame}, state) do
    {:stop, :normal, {1000, "shell closed"}, state}
  end

  def handle_info({:tunnel, _stream, _op, _frame}, state), do: {:ok, state}

  def handle_info(:ping, state) do
    schedule_ping()
    {:push, {:text, Jason.encode!(%{"type" => "ping"})}, state}
  end

  def handle_info(_msg, state), do: {:ok, state}

  @impl true
  # Closing the channel then the connection is what kills the root shell on the
  # box; leaving it would strand a live login there.
  def terminate(_reason, %__MODULE__{transport: :ssh} = state) do
    Orbit.Securepoint.SSH.close_interactive(state.ssh_conn, state.ssh_chan)
    :ok
  end

  def terminate(_reason, %__MODULE__{stream: nil}), do: :ok

  def terminate(_reason, state) do
    # Closing our end drops the hub stream (which tells the agent to kill the
    # PTY); the slot frees when this process dies (Shell.Slots monitors it).
    Hub.close_tunnel(state.stream)
    :ok
  end

  defp schedule_ping, do: Process.send_after(self(), :ping, @ping_interval_ms)
end
