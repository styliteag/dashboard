defmodule OrbitWeb.AgentSocket do
  @moduledoc """
  Raw WebSocket handler for `/api/ws/agent` — the agent side of the wire
  protocol pinned in docs/agent-architecture.md §27. Deliberately NOT a
  Phoenix channel: the fleet speaks plain JSON text frames.

  Auth happened in the plug (bearer token → instance) before the upgrade;
  this process owns exactly one agent connection. Frame dispatch mirrors
  ws.py:169-215: hello→welcome, metrics→ingest+stamp, command_result→
  resolve future, pong→counter, tunnel→(ported with the stream features).
  """

  @behaviour WebSock

  require Logger

  alias Orbit.Hub

  defstruct [:instance_id, :instance_name, :push_interval, :source_ip, hello_seen: false]

  @impl true
  def init(%{auth_error: {code, message}}) do
    # Python hub accepts, sends an error frame, then closes 4001/4003 —
    # keep that exact sequence for the fleet's reconnect loops (§27.1).
    error = Jason.encode!(%{"type" => "error", "message" => message})
    {:stop, :normal, {code, message}, [{:text, error}], %__MODULE__{}}
  end

  def init(%{instance: instance} = arg) do
    push_interval =
      instance.push_interval_seconds || Orbit.Settings.effective("push_interval_seconds")

    {:ok,
     %__MODULE__{
       instance_id: instance.id,
       instance_name: instance.name,
       push_interval: push_interval,
       source_ip: arg[:source_ip]
     }}
  end

  # Linux nodes only: no other platform runs the vendored script.
  defp maybe_refresh_checkmk(instance_id, "linux", reported_sha) do
    served = Orbit.Agent.Package.checkmk_sha256()

    cond do
      is_nil(served) ->
        :ok

      to_string(reported_sha) == served ->
        :ok

      true ->
        case Orbit.Agent.Package.checkmk_update_params() do
          {:ok, params} ->
            result = Orbit.Hub.send_command(instance_id, "checkmk.update", params, 60_000)

            Logger.info(
              "checkmk.update instance_id=#{instance_id} served=#{String.slice(served, 0, 12)} " <>
                "result=#{inspect(Map.get(result, "output", result))}"
            )

          {:error, :unavailable} ->
            :ok
        end
    end
  end

  defp maybe_refresh_checkmk(_instance_id, _platform, _sha), do: :ok

  @impl true
  def handle_in({text, [opcode: :text]}, state) do
    case Jason.decode(text) do
      {:ok, frame} ->
        dispatch(frame, state)

      {:error, _} ->
        Hub.bump(:json_errors)
        {:ok, state}
    end
  end

  # Agent never sends binary; ignore (agent ignores inbound binary likewise).
  def handle_in(_other, state), do: {:ok, state}

  defp dispatch(%{"type" => "hello"} = hello, state) do
    Hub.register(state.instance_id, %{
      agent_version: hello["agent_version"],
      platform: hello["platform"],
      checkmk_sha256: hello["checkmk_sha256"],
      source_ip: state.source_ip
    })

    Logger.info(
      "agent.connected instance_id=#{state.instance_id} version=#{hello["agent_version"]} platform=#{hello["platform"]}"
    )

    # The box knows what it is; the enrolment form only guessed. Best-effort
    # and off the connect path — a DB hiccup must never cost the agent its
    # session.
    Task.start(fn ->
      Orbit.Instances.heal_device_type(state.instance_id, hello["platform"])
    end)

    # The vendored check_mk_agent is what produces every metric on a Linux
    # node, and the agent has reported its sha256 in the hello frame all
    # along — nothing ever read it, so bumping the vendored script never
    # reached the fleet. Push a refresh when they differ. Off the connect
    # path and best-effort: the agent verifies sha256 AND the Ed25519
    # signature before writing, so a failure here costs one cycle, nothing
    # more.
    Task.start(fn ->
      maybe_refresh_checkmk(state.instance_id, hello["platform"], hello["checkmk_sha256"])
    end)

    welcome = %{
      "type" => "welcome",
      "instance_id" => state.instance_id,
      "instance_name" => state.instance_name,
      "push_interval" => state.push_interval
    }

    # Re-push the monitor sets right after the welcome — the agent's sets
    # start EMPTY on every (re)connect and are only populated by a
    # config_update; without this, monitors stay unprobed until someone
    # edits them (ws.py:149 parity). Best-effort: a failure here must never
    # tear down the agent connection.
    Task.start(fn -> Orbit.Monitors.push_to_agent(state.instance_id) end)

    {:push, {:text, Jason.encode!(welcome)}, %{state | hello_seen: true}}
  end

  defp dispatch(%{"type" => "metrics", "data" => data}, state) when is_map(data) do
    Hub.record_push(state.instance_id)
    Hub.ingest_metrics(state.instance_id, data)
    # Diff + alert check-state transitions off the socket path (own GenServer).
    Orbit.Checks.Transitions.push_evaluated(state.instance_id)
    stamp_last_seen(state.instance_id, data["ts"])
    {:ok, state}
  end

  defp dispatch(%{"type" => "command_result"} = frame, state) do
    Hub.resolve_command(frame["request_id"], frame["result"] || %{})
    {:ok, state}
  end

  defp dispatch(%{"type" => "pong"}, state) do
    Hub.record_pong(state.instance_id)
    {:ok, state}
  end

  # Agent→hub tunnel frames (data/close/started/error) route by stream id to
  # the consumer process the hub registered at open (§27.5).
  defp dispatch(%{"type" => "tunnel", "stream" => _} = frame, state) do
    Hub.deliver_tunnel(frame)
    {:ok, state}
  end

  defp dispatch(_unknown, state) do
    Hub.bump(:unknown_messages)
    {:ok, state}
  end

  @impl true
  def handle_info({:push_frame, frame}, state) do
    {:push, {:text, Jason.encode!(frame)}, state}
  end

  def handle_info(:hub_replaced, state) do
    # A newer connection for this instance registered — close this one
    # (python hub closes the old ws in register; 1000 = normal).
    {:stop, :normal, {1000, "replaced"}, state}
  end

  def handle_info(_other, state), do: {:ok, state}

  @impl true
  def terminate(_reason, %__MODULE__{instance_id: nil}), do: :ok

  def terminate(_reason, state) do
    Hub.unregister(state.instance_id)
    Logger.info("agent.disconnected instance_id=#{state.instance_id}")
    :ok
  end

  # agent_last_seen + last_success_at stamping per push (hub.py:706-717) —
  # Orbit.Availability also detects the offline→online edge here and fires
  # the recovered alert. Never raises; failures must never kill the socket.
  defp stamp_last_seen(instance_id, ts) do
    now = parse_ts(ts) || DateTime.utc_now()
    Orbit.Availability.stamp_push(instance_id, now)
  end

  defp parse_ts(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp parse_ts(_), do: nil
end
