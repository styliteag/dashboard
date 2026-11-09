defmodule OrbitWeb.WSOriginRequiredTest do
  @moduledoc """
  Shell and capture WebSockets carry a root shell / packet capture and are
  only ever opened by the dashboard page. A handshake without an Origin, or
  with the opaque `null` origin (sandboxed iframe, file://, data: URL), is
  refused 4403 before the session is looked at. The agent WS
  (/api/ws/agent) does not go through WSAuth.
  """
  use OrbitWeb.ConnCase

  alias OrbitWeb.WSAuth

  test "missing Origin is 4403", %{conn: conn} do
    assert {:error, 4403} = WSAuth.authenticate(conn)
  end

  test "Origin: null is 4403", %{conn: conn} do
    assert {:error, 4403} = WSAuth.authenticate(Plug.Conn.put_req_header(conn, "origin", "null"))
  end

  test "an origin without a host is 4403", %{conn: conn} do
    assert {:error, 4403} =
             WSAuth.authenticate(Plug.Conn.put_req_header(conn, "origin", "file://"))
  end
end
