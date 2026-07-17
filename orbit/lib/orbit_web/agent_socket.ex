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

  defstruct [:instance_id, :instance_name, :push_interval, hello_seen: false]

  @impl true
  def init(%{auth_error: {code, message}}) do
    # Python hub accepts, sends an error frame, then closes 4001/4003 —
    # keep that exact sequence for the fleet's reconnect loops (§27.1).
    error = Jason.encode!(%{"type" => "error", "message" => message})
    {:stop, :normal, {code, message}, [{:text, error}], %__MODULE__{}}
  end

  def init(%{instance: instance}) do
    push_interval =
      instance.push_interval_seconds || Orbit.Settings.effective("push_interval_seconds")

    {:ok,
     %__MODULE__{
       instance_id: instance.id,
       instance_name: instance.name,
       push_interval: push_interval
     }}
  end

  @impl true
  def handle_in({text, [opcode: :text]}, state) do
    case Jason.decode(text) do
      {:ok, frame} -> dispatch(frame, state)
      {:error, _} -> {:ok, state}
    end
  end

  # Agent never sends binary; ignore (agent ignores inbound binary likewise).
  def handle_in(_other, state), do: {:ok, state}

  defp dispatch(%{"type" => "hello"} = hello, state) do
    Hub.register(state.instance_id, %{
      agent_version: hello["agent_version"],
      platform: hello["platform"],
      checkmk_sha256: hello["checkmk_sha256"]
    })

    Logger.info(
      "agent.connected instance_id=#{state.instance_id} version=#{hello["agent_version"]} platform=#{hello["platform"]}"
    )

    welcome = %{
      "type" => "welcome",
      "instance_id" => state.instance_id,
      "instance_name" => state.instance_name,
      "push_interval" => state.push_interval
    }

    {:push, {:text, Jason.encode!(welcome)}, %{state | hello_seen: true}}
  end

  defp dispatch(%{"type" => "metrics", "data" => data}, state) when is_map(data) do
    Hub.record_push(state.instance_id)
    Hub.ingest_metrics(state.instance_id, data)
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

  defp dispatch(_unknown, state), do: {:ok, state}

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

  # agent_last_seen + last_success_at stamping per push (hub.py:706-717).
  # Update-query keeps it fire-and-forget; failures must never kill the socket.
  defp stamp_last_seen(instance_id, ts) do
    now = parse_ts(ts) || DateTime.utc_now()
    naive = now |> DateTime.truncate(:second) |> DateTime.to_naive()

    Orbit.Repo.query(
      "UPDATE instances SET agent_last_seen = ?, last_success_at = ?, last_error_at = NULL WHERE id = ?",
      [naive, naive, instance_id]
    )
    |> case do
      {:ok, _} -> :ok
      {:error, err} -> Logger.warning("agent.stamp_failed #{inspect(err)}")
    end
  end

  defp parse_ts(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp parse_ts(_), do: nil
end
