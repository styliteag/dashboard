defmodule Orbit.Poller.OpnsenseClientLimitsTest do
  @moduledoc """
  The direct-poll client sends the API key/secret as basic auth: it never
  follows a redirect (the key would travel to wherever the box points), and
  a response body above the cap is refused instead of buffered in full.
  """
  use ExUnit.Case, async: true

  alias Orbit.Poller.OpnsenseClient, as: C

  setup do
    %{client: %C{base_url: "https://box:4444", api_key: "k", api_secret: "s", ssl_verify: false}}
  end

  test "a redirect is not followed", %{client: client} do
    test_pid = self()

    Req.Test.stub(Orbit.Poller.OpnsenseClient, fn conn ->
      send(test_pid, {:hit, conn.host, conn.request_path})

      conn
      |> Plug.Conn.put_resp_header("location", "https://evil.example/steal")
      |> Plug.Conn.send_resp(302, "")
    end)

    assert {:error, _} = C.api_json(client, "GET", "/api/core/firmware/status", nil)
    assert {:error, _} = C.api_json(client, "POST", "/api/core/firmware/check", %{})
    assert_received {:hit, "box", _}
    assert_received {:hit, "box", _}
    refute_received {:hit, "evil.example", _}
  end

  test "an oversized body is refused", %{client: client} do
    Req.Test.stub(Orbit.Poller.OpnsenseClient, fn conn ->
      Req.Test.json(conn, %{"blob" => String.duplicate("a", 40_000_000)})
    end)

    assert {:error, _} = C.api_json(client, "GET", "/api/core/firmware/status", nil)
  end

  test "a normal JSON body still decodes", %{client: client} do
    Req.Test.stub(Orbit.Poller.OpnsenseClient, fn conn -> Req.Test.json(conn, %{"ok" => 1}) end)
    assert {:ok, %{"ok" => 1}} = C.api_json(client, "GET", "/x", nil)
  end
end
