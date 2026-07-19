defmodule Orbit.Hub.TunnelTest do
  @moduledoc "Tunnel multiplex routing (§27.5) — open/data/resize/close + consumer-death cleanup."
  use ExUnit.Case, async: true

  alias Orbit.Hub

  setup do
    hub = start_supervised!({Hub, name: nil})
    # Register a fake agent socket = this test process, so pushed frames land
    # in our mailbox as {:push_frame, frame}.
    :ok = Hub.register(hub, 7, %{agent_version: "3.1.8", platform: "pfsense"})
    %{hub: hub}
  end

  test "open sends an open frame and returns a stream id", %{hub: hub} do
    assert {:ok, stream} =
             Hub.open_tunnel(hub, 7, %{"kind" => "shell", "rows" => 24, "cols" => 80})

    assert_receive {:push_frame,
                    %{
                      "type" => "tunnel",
                      "op" => "open",
                      "stream" => ^stream,
                      "kind" => "shell",
                      "rows" => 24,
                      "cols" => 80
                    }}
  end

  test "open to a disconnected instance", %{hub: hub} do
    assert {:error, :not_connected} = Hub.open_tunnel(hub, 99, %{})
  end

  test "tunnel_send base64-frames data to the agent", %{hub: hub} do
    {:ok, stream} = Hub.open_tunnel(hub, 7, %{})
    assert_receive {:push_frame, %{"op" => "open"}}
    Hub.tunnel_send(hub, stream, "hello")
    assert_receive {:push_frame, %{"op" => "data", "stream" => ^stream, "data" => data}}
    assert Base.decode64!(data) == "hello"
  end

  test "resize forwards rows/cols", %{hub: hub} do
    {:ok, stream} = Hub.open_tunnel(hub, 7, %{})
    assert_receive {:push_frame, %{"op" => "open"}}
    Hub.tunnel_resize(hub, stream, 40, 120)
    assert_receive {:push_frame, %{"op" => "resize", "rows" => 40, "cols" => 120}}
  end

  test "agent→hub data frames route to the consumer; agent close ends the stream",
       %{hub: hub} do
    {:ok, stream} = Hub.open_tunnel(hub, 7, %{})
    assert_receive {:push_frame, %{"op" => "open"}}

    Hub.deliver_tunnel(hub, %{
      "type" => "tunnel",
      "op" => "data",
      "stream" => stream,
      "data" => Base.encode64("pcap-bytes")
    })

    assert_receive {:tunnel, ^stream, "data", %{"data" => d}}
    assert Base.decode64!(d) == "pcap-bytes"

    # An agent-side close reaches the consumer and drops routing (no echo back
    # to the agent).
    Hub.deliver_tunnel(hub, %{"type" => "tunnel", "op" => "close", "stream" => stream})
    assert_receive {:tunnel, ^stream, "close", _}

    # Sending after close is a no-op (routing gone) — no frame pushed.
    Hub.tunnel_send(hub, stream, "late")
    refute_receive {:push_frame, %{"op" => "data"}}, 50
  end

  test "close_tunnel tells the agent and drops routing", %{hub: hub} do
    {:ok, stream} = Hub.open_tunnel(hub, 7, %{})
    assert_receive {:push_frame, %{"op" => "open"}}
    Hub.close_tunnel(hub, stream)
    assert_receive {:push_frame, %{"op" => "close", "stream" => ^stream}}
  end

  test "a dying consumer's streams are closed toward the agent", %{hub: hub} do
    parent = self()

    consumer =
      spawn(fn ->
        {:ok, stream} = Hub.open_tunnel(hub, 7, %{})
        send(parent, {:opened, stream})
        receive do: (:die -> :ok)
      end)

    assert_receive {:opened, stream}
    # The open frame was pushed to us (the fake agent).
    assert_receive {:push_frame, %{"op" => "open", "stream" => ^stream}}

    send(consumer, :die)
    # Hub's DOWN handler closes the stream toward the agent.
    assert_receive {:push_frame, %{"op" => "close", "stream" => ^stream}}
  end
end
