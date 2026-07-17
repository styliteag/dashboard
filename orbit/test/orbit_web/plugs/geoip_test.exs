defmodule OrbitWeb.Plugs.GeoIPTest do
  @moduledoc """
  Gate plug semantics with an injected verdict (test seam) — the real
  evaluate chain is covered by Orbit.GeoIP.RulesTest; the mmdb path is
  proven live. async: false: mutates the :geoip_evaluator application env.
  """

  use ExUnit.Case, async: false

  import Plug.Test

  alias OrbitWeb.Plugs.GeoIP

  setup do
    on_exit(fn -> Application.delete_env(:orbit, :geoip_evaluator) end)
    :ok
  end

  defp deny_all do
    Application.put_env(:orbit, :geoip_evaluator, fn _ip -> {:deny, "country_blocked", "RU"} end)
  end

  defp call(conn), do: GeoIP.call(conn, [])

  test "default rules (disabled) allow everything" do
    conn = call(conn(:get, "/instances"))
    refute conn.halted
  end

  test "agent ws, enroll and health are exempt even when denying" do
    deny_all()

    for path <- ["/api/ws/agent", "/api/agent/enroll", "/api/health-ex"] do
      refute call(conn(:get, path)).halted, "expected #{path} to be exempt"
    end
  end

  test "orbit_ api keys bypass the gate (machine reads)" do
    deny_all()

    conn =
      conn(:get, "/api/instances")
      |> Plug.Conn.put_req_header("authorization", "Bearer orbit_abc123")
      |> call()

    refute conn.halted
  end

  test "denied browser path: 403 plain text, halted, no country named" do
    deny_all()
    conn = call(conn(:get, "/instances"))
    assert conn.halted
    assert conn.status == 403
    assert conn.resp_body == "access restricted from your location"
  end

  test "denied api path: 403 json" do
    deny_all()
    conn = call(conn(:get, "/api/instances"))
    assert conn.halted
    assert conn.status == 403
    assert Jason.decode!(conn.resp_body) == %{"detail" => "access restricted from your location"}
  end

  test "denied login POST still answers 403 when the audit write fails" do
    # No DB in tests: Audit.write raises inside — the rescue must keep the
    # deny intact (an audit hiccup must not 500 the deny).
    deny_all()
    conn = call(conn(:post, "/login"))
    assert conn.halted
    assert conn.status == 403
  end

  test "fail-open verdict (db_unavailable) passes the request through" do
    Application.put_env(:orbit, :geoip_evaluator, fn _ip -> {:allow, "db_unavailable", nil} end)
    refute call(conn(:get, "/instances")).halted
  end
end
