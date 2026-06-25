"""Tests for the prod GUI-proxy Caddyfile builder (slug → port → instance-id).

The render is security-relevant: each vhost must bake its own instance id into the
forward_auth check (cross-tenant gate) and map to the stable 14400+id forwarder port.
"""

from __future__ import annotations

from app.agent_hub.gui_caddy import FORWARDER_BASE, bootstrap_caddyfile, build_caddyfile


def test_bootstrap_has_admin_and_empty_wildcard() -> None:
    out = bootstrap_caddyfile()
    assert "admin 0.0.0.0:2019" in out
    assert "auto_https off" in out
    assert "http://*.{$ORBIT_GUI_DOMAIN} {" in out
    assert "@gui-" not in out  # no per-instance vhosts in the bootstrap


def test_build_maps_slug_host_port_and_instance() -> None:
    out = build_caddyfile([("opn1", 3), ("firewall-buero-sued", 7)])

    assert "@gui-opn1 host gui-opn1.{$ORBIT_GUI_DOMAIN}" in out
    # port is the stable 14400+id; instance id is the second snippet arg
    assert f"import gui_vhost {FORWARDER_BASE + 3} 3" in out
    assert "@gui-firewall-buero-sued host gui-firewall-buero-sued.{$ORBIT_GUI_DOMAIN}" in out
    assert f"import gui_vhost {FORWARDER_BASE + 7} 7" in out


def test_authcheck_instance_is_baked_per_vhost() -> None:
    # The shared snippet derives the instance from args[1] → each handle passes its id.
    out = build_caddyfile([("opn1", 3)])
    assert "uri /api/gui/authcheck?instance={args[1]}" in out
    assert "import gui_vhost 14403 3" in out
