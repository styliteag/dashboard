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

  test "each instance gets a host-matched vhost importing its port + id" do
    file = Caddy.build_caddyfile([{"opn1", 3}, {"pf1", 4}])
    assert file =~ "@gui-opn1 host gui-opn1.{$ORBIT_GUI_DOMAIN}"
    assert file =~ "import gui_vhost 14403 3"
    assert file =~ "@gui-pf1 host gui-pf1.{$ORBIT_GUI_DOMAIN}"
    assert file =~ "import gui_vhost 14404 4"
  end
end
