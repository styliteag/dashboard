defmodule Orbit.GUI.CaddyTest do
  @moduledoc "build_caddyfile port — stable forwarder ports, per-slug vhosts."

  use ExUnit.Case, async: true

  alias Orbit.GUI.Caddy

  test "forwarder port is a stable 14400 + id" do
    assert Caddy.port_for(3) == 14_403
    assert Caddy.port_for(7) == 14_407
  end

  test "bootstrap file has the global block and no vhosts" do
    file = Caddy.bootstrap_caddyfile()
    assert file =~ "admin 0.0.0.0:2019"
    assert file =~ "(gui_vhost)"
    refute file =~ "@gui-"
  end

  describe "reconcile gating" do
    setup do
      on_exit(fn ->
        Application.put_env(:orbit, :gui_proxy_enabled, false)
        Application.put_env(:orbit, :gui_caddy_admin_url, "")
      end)
    end

    test "a disabled proxy costs nothing — no push, no spawned task" do
      Application.put_env(:orbit, :gui_proxy_enabled, false)
      Application.put_env(:orbit, :gui_caddy_admin_url, "http://caddy:2019/load")

      refute Caddy.reconcile()
      # reconcile_async now rides every instance create/update/delete, so the
      # gate has to be checked BEFORE spawning: an unconfigured deployment
      # must not start a task (and hit the DB) on every write.
      assert Caddy.reconcile_async() == :ok
    end

    test "an enabled proxy with no admin url is still a no-op" do
      Application.put_env(:orbit, :gui_proxy_enabled, true)
      Application.put_env(:orbit, :gui_caddy_admin_url, "")

      refute Caddy.reconcile()
    end

    test "a configured proxy posts a caddyfile to the admin api" do
      Application.put_env(:orbit, :gui_proxy_enabled, true)
      Application.put_env(:orbit, :gui_caddy_admin_url, "http://caddy:2019/load")
      test_pid = self()

      plug = fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        send(test_pid, {:pushed, body, Plug.Conn.get_req_header(conn, "content-type")})
        Plug.Conn.resp(conn, 200, "")
      end

      assert Caddy.reconcile(req_plug: plug)
      assert_received {:pushed, body, ["text/caddyfile"]}
      assert body =~ "admin 0.0.0.0:2019"
    end
  end

  test "each instance gets a host-matched vhost importing its port + id" do
    file = Caddy.build_caddyfile([{"opn1", 3}, {"pf1", 4}])
    assert file =~ "@gui-opn1 host gui-opn1.{$ORBIT_GUI_DOMAIN}"
    assert file =~ "import gui_vhost 14403 3"
    assert file =~ "@gui-pf1 host gui-pf1.{$ORBIT_GUI_DOMAIN}"
    assert file =~ "import gui_vhost 14404 4"
  end
end
