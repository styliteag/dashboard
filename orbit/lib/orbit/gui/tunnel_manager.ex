defmodule Orbit.GUI.TunnelManager do
  @moduledoc """
  In-container TCP forwarders for the GUI proxy — port of gui_tunnel.py.
  `ensure/1` binds a stable per-instance port (14400 + id, never reused →
  a per-origin cookie can't leak across firewalls) on demand and returns
  it; each accepted socket is bridged to the firewall's GUI port through
  the instance's agent over the hub tunnel (Orbit.Hub.open_tunnel). A
  Caddy vhost fronts it with a per-instance origin + TLS.

  The listener is internal and gated by forward_auth, so idle reaping is
  housekeeping, not a security boundary: a forwarder with no active
  connections is closed after `gui_idle_minutes`; the next Open GUI
  re-opens it.

  One GenServer owns the port→acceptor map; each accepted connection runs
  in its own linked process so one connection can never take down the
  listener.
  """

  use GenServer

  require Logger

  @forwarder_base 14_400

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  def port_for(instance_id), do: @forwarder_base + instance_id

  @doc "Ensure a forwarder is running for this instance; returns {:ok, port}."
  def ensure(server \\ __MODULE__, instance_id) do
    GenServer.call(server, {:ensure, instance_id})
  end

  @doc "Reap forwarders idle (no active connections) ≥ idle_minutes."
  def reap_idle(server \\ __MODULE__, idle_minutes) do
    GenServer.cast(server, {:reap, idle_minutes})
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(opts) do
    # opts[:hub] overrides the hub (tests); opts[:reap_ms] arms the reaper.
    hub = Keyword.get(opts, :hub, Orbit.Hub)

    if ms = Keyword.get(opts, :reap_ms), do: Process.send_after(self(), :reap, ms)

    {:ok, %{slots: %{}, hub: hub, reap_ms: Keyword.get(opts, :reap_ms)}}
  end

  @impl true
  def handle_call({:ensure, instance_id}, _from, state) do
    case state.slots[instance_id] do
      %{port: port} ->
        {:reply, {:ok, port}, state}

      nil ->
        port = port_for(instance_id)

        # Bind loopback only — the GuiProxy plug reaches it at 127.0.0.1;
        # never exposed to the host (host-matched proxy is the front door).
        case :gen_tcp.listen(port, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}]) do
          {:ok, lsock} ->
            parent = self()
            acceptor = spawn_link(fn -> accept_loop(lsock, instance_id, state.hub, parent) end)

            slot = %{port: port, lsock: lsock, acceptor: acceptor, active: 0, idle_since: now()}
            {:reply, {:ok, port}, put_in(state.slots[instance_id], slot)}

          {:error, reason} ->
            Logger.warning(
              "gui_tunnel.listen_failed instance=#{instance_id} reason=#{inspect(reason)}"
            )

            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_cast({:reap, idle_minutes}, state) do
    {:noreply, do_reap(state, idle_minutes * 60)}
  end

  def handle_cast({:conn_delta, instance_id, delta}, state) do
    state =
      update_in(state.slots[instance_id], fn
        nil ->
          nil

        slot ->
          active = max(slot.active + delta, 0)
          %{slot | active: active, idle_since: if(active == 0, do: now(), else: nil)}
      end)

    {:noreply, state}
  end

  @impl true
  def handle_info(:reap, state) do
    if state.reap_ms, do: Process.send_after(self(), :reap, state.reap_ms)
    idle_minutes = Orbit.Settings.effective("gui_idle_minutes")
    {:noreply, if(idle_minutes > 0, do: do_reap(state, idle_minutes * 60), else: state)}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  defp do_reap(state, idle_seconds) do
    now = now()

    {reap, keep} =
      Enum.split_with(state.slots, fn {_id, s} ->
        s.active <= 0 and s.idle_since != nil and now - s.idle_since >= idle_seconds
      end)

    for {id, s} <- reap do
      :gen_tcp.close(s.lsock)
      Logger.info("gui_tunnel.reaped_idle instance=#{id}")
    end

    %{state | slots: Map.new(keep)}
  end

  # -- acceptor + bridge (per-connection processes) -------------------------

  defp accept_loop(lsock, instance_id, hub, manager) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        GenServer.cast(manager, {:conn_delta, instance_id, 1})

        pid =
          spawn(fn ->
            try do
              bridge(sock, instance_id, hub)
            after
              GenServer.cast(manager, {:conn_delta, instance_id, -1})
            end
          end)

        :gen_tcp.controlling_process(sock, pid)
        send(pid, :go)
        accept_loop(lsock, instance_id, hub, manager)

      {:error, :closed} ->
        :ok

      {:error, _reason} ->
        accept_loop(lsock, instance_id, hub, manager)
    end
  end

  # Bridge one accepted socket to the firewall GUI through the agent tunnel.
  # The bridge process is the tunnel consumer: it receives {:tunnel, stream,
  # op, frame} from the hub and pipes bytes both ways.
  defp bridge(sock, instance_id, hub) do
    receive do
      :go -> :ok
    after
      1000 -> :ok
    end

    case Orbit.Hub.open_tunnel(hub, instance_id, %{}) do
      {:ok, stream} ->
        :inet.setopts(sock, active: true)
        pump(sock, stream, hub)
        Orbit.Hub.close_tunnel(hub, stream)

      {:error, :not_connected} ->
        :gen_tcp.close(sock)
    end
  end

  defp pump(sock, stream, hub) do
    receive do
      {:tcp, ^sock, data} ->
        Orbit.Hub.tunnel_send(hub, stream, data)
        pump(sock, stream, hub)

      {:tcp_closed, ^sock} ->
        :ok

      {:tcp_error, ^sock, _reason} ->
        :ok

      {:tunnel, ^stream, "data", frame} ->
        case Base.decode64(frame["data"] || "") do
          {:ok, bytes} -> :gen_tcp.send(sock, bytes)
          _ -> :ok
        end

        pump(sock, stream, hub)

      {:tunnel, ^stream, "close", _frame} ->
        :gen_tcp.close(sock)

      {:tunnel, ^stream, _op, _frame} ->
        pump(sock, stream, hub)
    end
  end

  defp now, do: System.monotonic_time(:second)
end
