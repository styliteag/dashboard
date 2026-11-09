defmodule OrbitWeb.ApiSecureHeadersTest do
  @moduledoc """
  The session/write/read API pipelines serve raw text (logfiles, config
  backups, CSV, Prometheus) — they carry the secure browser headers
  (x-content-type-options: nosniff etc.) like the browser pipeline.
  """
  use OrbitWeb.ConnCase

  test "session, write and read API responses carry nosniff", %{conn: conn} do
    for {method, path} <- [
          {:get, "/api/agents/connected"},
          {:post, "/api/instances/1/agent/update"},
          {:get, "/api/export/prometheus"}
        ] do
      resp = dispatch(conn, @endpoint, method, path, nil)
      assert get_resp_header(resp, "x-content-type-options") == ["nosniff"], path
    end
  end
end
