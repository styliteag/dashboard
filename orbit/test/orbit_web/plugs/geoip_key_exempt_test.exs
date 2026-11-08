defmodule OrbitWeb.Plugs.GeoIPKeyExemptTest do
  @moduledoc """
  The `orbit_` bearer exemption must not be a header anyone can add: it only
  applies on paths whose auth is the bearer key ALONE (a wrong key is a 401
  there, never a session fallback). A blocked browser session adding
  `Authorization: Bearer orbit_x` to a UI or session-API request stays
  blocked. async: false — mutates the :geoip_evaluator env.
  """
  use ExUnit.Case, async: false

  import Plug.Test

  alias OrbitWeb.Plugs.GeoIP

  setup do
    Application.put_env(:orbit, :geoip_evaluator, fn _ip -> {:deny, "country_blocked", "RU"} end)
    on_exit(fn -> Application.delete_env(:orbit, :geoip_evaluator) end)
  end

  defp with_key(path, method \\ :get, scheme \\ "Bearer") do
    conn(method, path)
    |> Plug.Conn.put_req_header("authorization", "#{scheme} orbit_forged")
    |> GeoIP.call([])
  end

  test "UI, session-API and write-API paths stay gated despite a bearer header" do
    for path <- ["/instances", "/api/instances/1/comments", "/api/export/instances.csv", "/login"],
        do: assert(with_key(path).halted, path)

    assert with_key("/api/instances/1/gui/open", :post).halted
  end

  test "key-only machine paths are exempt" do
    for path <- ["/api/export/prometheus", "/api/export/checkmk"],
        do: refute(with_key(path).halted, path)
  end

  test "a lower-case scheme (which key auth does not accept) is not exempt" do
    assert with_key("/api/export/prometheus", :get, "bearer").halted
  end

  test ":geoip_key_auth_prefixes unset: only the built-in export paths are exempt" do
    OrbitWeb.TestHooks.delete_hook(:geoip_key_auth_prefixes)
    assert with_key("/api/ext/v1/hosts").halted
  end

  test ":geoip_key_auth_prefixes adds whole path segments, not look-alike prefixes" do
    OrbitWeb.TestHooks.put_hook(:geoip_key_auth_prefixes, ["/api/ext/v1"])

    refute with_key("/api/ext/v1").halted
    refute with_key("/api/ext/v1/hosts").halted
    assert with_key("/api/ext/v1x").halted
    assert with_key("/instances").halted
  end
end
