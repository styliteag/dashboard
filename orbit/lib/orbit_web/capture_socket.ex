defmodule OrbitWeb.CaptureSocket do
  @moduledoc """
  Live pcap stream from an agent to a browser tab (§27.7). Consumer of a
  `kind:"capture"` tunnel: forwards the raw pcap byte stream as BINARY WS
  frames; agent `started`/`error` ops become JSON control frames; a client
  `{"type":"stop"}` tears the capture down.

  Streams the box's full raw packet contents — authorization (origin,
  session, write role, instance scope, connected agent) happened in the
  controller BEFORE the upgrade (regression b622b6f: this endpoint once
  shipped unauthenticated and streamed any box's traffic to any origin).
  """

  @behaviour WebSock

  alias Orbit.Hub

  defstruct [:instance_id, :stream]

  @impl true
  def init(%{auth_error: code}) do
    {:stop, :normal, {code, "unauthorized"}, %__MODULE__{}}
  end

  def init(%{instance_id: instance_id, interface: interface, filter: filter}) do
    open_extra = %{"kind" => "capture", "interface" => interface, "filter" => filter}

    case Hub.open_tunnel(instance_id, open_extra) do
      {:ok, stream} ->
        {:ok, %__MODULE__{instance_id: instance_id, stream: stream}}

      {:error, :not_connected} ->
        {:stop, :normal, {4404, "agent not connected"}, %__MODULE__{}}
    end
  end

  @impl true
  def handle_in({text, [opcode: :text]}, state) do
    case Jason.decode(text) do
      {:ok, %{"type" => "stop"}} -> {:stop, :normal, {1000, "stopped"}, state}
      _ -> {:ok, state}
    end
  end

  def handle_in(_other, state), do: {:ok, state}

  @impl true
  # Raw pcap chunks → binary frames to the browser.
  def handle_info({:tunnel, _stream, "data", frame}, state) do
    case Base.decode64(frame["data"] || "") do
      {:ok, bytes} -> {:push, {:binary, bytes}, state}
      :error -> {:ok, state}
    end
  end

  def handle_info({:tunnel, _stream, "started", _frame}, state) do
    {:push, {:text, Jason.encode!(%{"type" => "started"})}, state}
  end

  def handle_info({:tunnel, _stream, "error", frame}, state) do
    {:push, {:text, Jason.encode!(%{"type" => "error", "message" => frame["data"] || ""})}, state}
  end

  def handle_info({:tunnel, _stream, "close", _frame}, state) do
    {:stop, :normal, {1000, "capture ended"}, state}
  end

  def handle_info(_msg, state), do: {:ok, state}

  @impl true
  def terminate(_reason, %__MODULE__{stream: nil}), do: :ok

  def terminate(_reason, state) do
    Hub.close_tunnel(state.stream)
    :ok
  end
end
