defmodule Orbit.Hub.FrameBindingTest do
  @moduledoc """
  A command_result / tunnel frame is accepted only from the socket of the
  instance the request or stream was opened for. Another enrolled agent that
  learns (or guesses) a request id or stream id cannot answer someone else's
  command or inject bytes into someone else's shell/GUI/capture stream.
  """
  use ExUnit.Case, async: true

  alias Orbit.Hub

  setup do
    hub = start_supervised!({Hub, name: nil})
    :ok = Hub.register(hub, 7, %{agent_version: "3.1.8", platform: "pfsense"})
    %{hub: hub}
  end

  test "a result from another instance's socket is ignored", %{hub: hub} do
    task = Task.async(fn -> Hub.send_command_on(hub, 7, "ping", %{}, 300) end)
    assert_receive {:push_frame, %{"type" => "command", "request_id" => rid}}

    Hub.resolve_command_from(hub, 8, rid, %{"success" => true, "output" => "forged"})
    Hub.resolve_command_from(hub, 7, rid, %{"success" => true, "output" => "real"})
    assert Task.await(task) == %{"success" => true, "output" => "real"}
  end

  test "a tunnel frame from another instance's socket is dropped", %{hub: hub} do
    {:ok, stream} = Hub.open_tunnel(hub, 7, %{})
    assert_receive {:push_frame, %{"op" => "open"}}

    frame = %{"type" => "tunnel", "op" => "data", "stream" => stream, "data" => "eA=="}
    Hub.deliver_tunnel_from(hub, 8, frame)
    refute_receive {:tunnel, ^stream, _, _}, 50

    Hub.deliver_tunnel_from(hub, 7, frame)
    assert_receive {:tunnel, ^stream, "data", _}
  end
end
