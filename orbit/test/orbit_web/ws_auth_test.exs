defmodule OrbitWeb.WSAuthTest do
  @moduledoc "Origin + write-role gates of the client-WS auth (session paths covered by the live shell E2E)."
  use OrbitWeb.ConnCase, async: true

  alias OrbitWeb.WSAuth

  setup %{conn: conn} do
    # WSAuth reads the session; the pipeline fetches it before the upgrade.
    %{conn: Plug.Test.init_test_session(conn, %{})}
  end

  defp with_origin(conn, origin), do: put_req_header(conn, "origin", origin)

  describe "origin check (hub.py _ws_origin_ok parity)" do
    test "no origin header passes (non-browser client)", %{conn: conn} do
      # No session → 4401, but origin passed (we didn't get 4403).
      assert {:error, 4401} = WSAuth.authenticate(conn)
    end

    test "localhost origin always passes (dev)", %{conn: conn} do
      assert {:error, 4401} = WSAuth.authenticate(with_origin(conn, "http://localhost:5173"))
    end

    test "127.0.0.1 origin always passes", %{conn: conn} do
      assert {:error, 4401} = WSAuth.authenticate(with_origin(conn, "http://127.0.0.1:4000"))
    end

    test "a foreign origin is rejected 4403 before session is even checked", %{conn: conn} do
      assert {:error, 4403} = WSAuth.authenticate(with_origin(conn, "https://evil.example.com"))
    end
  end
end
