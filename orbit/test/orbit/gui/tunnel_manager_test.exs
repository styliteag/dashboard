defmodule Orbit.GUI.TunnelManagerTest do
  @moduledoc """
  Functional bridge test — a real TCP client through the manager's listener,
  bridged to a private Hub where the test process is the agent socket
  (hub_test.exs pattern). Proves bytes flow both ways over the tunnel
  without a firewall: client→hub tunnel data frame, and a hub data frame→
  client socket.
  """

  use ExUnit.Case, async: false

  alias Orbit.GUI.TunnelManager
  alias Orbit.Hub

  setup do
    hub = start_supervised!({Hub, name: nil})
    # Register the test process as the agent for a high, unlikely-used id so
    # the forwarder port (14400+id) doesn't collide with anything.
    iid = 511
    :ok = Hub.register(hub, iid, %{agent_version: "test"})
    mgr = start_supervised!({TunnelManager, name: nil, hub: hub})
    %{hub: hub, mgr: mgr, iid: iid}
  end

  test "ensure binds the stable port and returns it", %{mgr: mgr, iid: iid} do
    assert {:ok, port} = TunnelManager.ensure(mgr, iid)
    assert port == 14_400 + iid
    # Idempotent — a second ensure returns the same port, no new listener.
    assert {:ok, ^port} = TunnelManager.ensure(mgr, iid)
  end

  test "a client socket bridges bytes both ways over the hub tunnel", ctx do
    {:ok, port} = TunnelManager.ensure(ctx.mgr, ctx.iid)
    {:ok, client} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 1000)

    # The bridge opens a tunnel — the agent (this process) sees the open frame.
    assert_receive {:push_frame, %{"type" => "tunnel", "op" => "open", "stream" => stream}}, 1000

    # Client → firewall: bytes arrive at the agent as a base64 data frame.
    :ok = :gen_tcp.send(client, "GET / HTTP/1.0\r\n\r\n")
    assert_receive {:push_frame, %{"op" => "data", "stream" => ^stream, "data" => b64}}, 1000
    assert Base.decode64!(b64) == "GET / HTTP/1.0\r\n\r\n"

    # Firewall → client: a hub-delivered data frame reaches the client socket.
    payload = "HTTP/1.0 200 OK\r\n\r\nhi"

    Hub.deliver_tunnel(ctx.hub, %{
      "stream" => stream,
      "op" => "data",
      "data" => Base.encode64(payload)
    })

    assert {:ok, ^payload} = :gen_tcp.recv(client, byte_size(payload), 1000)

    :gen_tcp.close(client)
  end
end
