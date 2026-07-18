defmodule Orbit.Poller.OpnsenseActionsTest do
  @moduledoc """
  Direct-poll action endpoints (firmware/ipsec/reboot) against a mocked
  OPNsense API — the agent-less arm of xsense/client.py. Req.Test plug, no
  real box; the method + path + response mapping are asserted.
  """
  use ExUnit.Case, async: true

  alias Orbit.Poller.OpnsenseClient, as: C

  setup do
    Application.put_env(:orbit, :opnsense_req_plug, {Req.Test, __MODULE__})
    on_exit(fn -> Application.delete_env(:orbit, :opnsense_req_plug) end)

    client = %C{base_url: "https://box:4444", api_key: "k", api_secret: "s", ssl_verify: false}
    %{client: client}
  end

  test "firmware_check POSTs the check endpoint and returns the status", %{client: client} do
    test_pid = self()

    Req.Test.stub(__MODULE__, fn conn ->
      send(test_pid, {:req, conn.method, conn.request_path})
      Req.Test.json(conn, %{"status" => "ok, updates available"})
    end)

    assert {:ok, "ok, updates available"} = C.firmware_check(client)
    assert_received {:req, "POST", "/api/core/firmware/check"}
  end

  test "firmware_update maps ok/not-ok status", %{client: client} do
    Req.Test.stub(__MODULE__, fn conn -> Req.Test.json(conn, %{"status" => "ok"}) end)
    assert {:ok, "ok"} = C.firmware_update(client)
  end

  test "firmware_upgrade_status splits the log", %{client: client} do
    Req.Test.stub(__MODULE__, fn conn ->
      Req.Test.json(conn, %{"status" => "running", "log" => "line1\nline2"})
    end)

    assert %{status: "running", log: ["line1", "line2"]} = C.firmware_upgrade_status(client)
  end

  test "ipsec_restart hits the service restart endpoint", %{client: client} do
    test_pid = self()

    Req.Test.stub(__MODULE__, fn conn ->
      send(test_pid, {:path, conn.request_path})
      Req.Test.json(conn, %{"status" => "ok"})
    end)

    assert {:ok, _} = C.ipsec_restart(client)
    assert_received {:path, "/api/ipsec/service/restart"}
  end

  test "reboot returns ok on {status: ok}", %{client: client} do
    Req.Test.stub(__MODULE__, fn conn -> Req.Test.json(conn, %{"status" => "ok"}) end)
    assert {:ok, _} = C.reboot(client)
  end

  test "a 500 answer is an error, not a crash", %{client: client} do
    Req.Test.stub(__MODULE__, fn conn -> Plug.Conn.send_resp(conn, 500, "boom") end)
    assert {:error, _} = C.firmware_check(client)
    assert {:error, _} = C.reboot(client)
  end
end
