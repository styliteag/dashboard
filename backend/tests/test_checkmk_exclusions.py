"""Tests for the Checkmk export exclusion matching (pure, DB-free)."""

from __future__ import annotations

from app.checkmk.exclusions import CATEGORIES, category, excluded_reason, is_excluded


def test_category_derivation() -> None:
    assert category("memory") == "memory"
    assert category("cpu") == "cpu"
    assert category("ipsec.service") == "ipsec.service"
    assert category("firmware") == "firmware"
    assert category("disk:/") == "disk"
    assert category("gateway:WAN") == "gateway"
    assert category("ipsec.tunnel:site-a") == "ipsec.tunnel"
    assert category("ipsec.tunnel_ping:site-a/10.0.5.0/24") == "ipsec.tunnel_ping"
    # IPv6 selector keeps only the first colon as the split point
    assert category("ipsec.tunnel_ping:site-a/2001:db8::/64") == "ipsec.tunnel_ping"
    assert category("load") == "load"
    assert category("swap") == "swap"
    assert category("pf_states") == "pf_states"
    assert category("ntp") == "ntp"
    assert category("service:sshd") == "service"
    assert category("cert:abc123") == "cert"
    assert category("iface_errors:igb0") == "iface_errors"
    assert category("connectivity:5") == "connectivity"


def test_all_categories_listed() -> None:
    # Must match every category the export can emit (see CATEGORIES note): the
    # evaluate_checks families plus the overlay services (agent/ping/http).
    assert set(CATEGORIES) == {
        "agent",
        "maintenance",
        "ping",
        "http",
        "memory",
        "cpu",
        "load",
        "swap",
        "disk",
        "gateway",
        "pf_states",
        "ntp",
        "ipsec.service",
        "ipsec.tunnel",
        "ipsec.tunnel_ping",
        "connectivity",
        "service",
        "cert",
        "iface_errors",
        "firmware",
    }


def test_no_rules_excludes_nothing() -> None:
    assert not is_excluded("cpu", 1, [])
    assert excluded_reason("gateway:WAN", 1, []) is None


def test_global_category_rule() -> None:
    rules = [(None, "cpu")]
    assert is_excluded("cpu", 1, rules)
    assert is_excluded("cpu", 99, rules)  # global → any instance
    assert excluded_reason("cpu", 1, rules) == "category"
    assert not is_excluded("memory", 1, rules)


def test_per_instance_specific_key_rule() -> None:
    rules = [(5, "gateway:WAN")]
    assert is_excluded("gateway:WAN", 5, rules)
    assert excluded_reason("gateway:WAN", 5, rules) == "specific"
    # other instance untouched
    assert not is_excluded("gateway:WAN", 6, rules)
    # other gateway on same instance untouched
    assert not is_excluded("gateway:LAN", 5, rules)


def test_per_instance_category_rule() -> None:
    rules = [(5, "gateway")]
    assert is_excluded("gateway:WAN", 5, rules)
    assert is_excluded("gateway:LAN", 5, rules)
    assert not is_excluded("gateway:WAN", 6, rules)


def test_category_rule_wins_reason_over_specific() -> None:
    rules = [(None, "gateway"), (1, "gateway:WAN")]
    assert excluded_reason("gateway:WAN", 1, rules) == "category"


def test_global_specific_key_rule() -> None:
    rules = [(None, "ipsec.tunnel_ping:site-a/10.0.5.0/24")]
    assert is_excluded("ipsec.tunnel_ping:site-a/10.0.5.0/24", 3, rules)
    assert excluded_reason("ipsec.tunnel_ping:site-a/10.0.5.0/24", 3, rules) == "specific"
    assert not is_excluded("ipsec.tunnel_ping:site-b/10.0.6.0/24", 3, rules)


def test_export_filtering_drops_only_matching_checks() -> None:
    """Mirrors how ``export_checkmk`` filters a list of check keys per instance."""
    keys = ["memory", "cpu", "gateway:WAN", "gateway:LAN", "firmware"]
    rules = [(None, "cpu"), (5, "gateway:WAN")]

    kept_5 = [k for k in keys if not is_excluded(k, 5, rules)]
    assert kept_5 == ["memory", "gateway:LAN", "firmware"]

    # A different instance keeps its own gateway:WAN but still loses cpu (global).
    kept_6 = [k for k in keys if not is_excluded(k, 6, rules)]
    assert "gateway:WAN" in kept_6
    assert "cpu" not in kept_6
