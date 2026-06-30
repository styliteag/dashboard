"""Tests for the unified service-selection logic (pure, DB-free).

A rule is ``(consumer, instance_id | None, selector, mode)``. The base default is
OFF for every consumer; ``include`` turns on, ``exclude`` mutes. Resolution is
most-specific-wins: instance beats global, full key beats category.
"""

from __future__ import annotations

from app.selection.model import (
    AVAILABILITY,
    CHANNELS,
    CHECK_CATEGORIES,
    CHECKMK,
    CONSUMERS,
    categories_for,
    category,
    is_on,
    resolve,
    valid_consumer,
    valid_mode,
    valid_selector,
)


def test_category_derivation() -> None:
    assert category("memory") == "memory"
    assert category("ipsec.service") == "ipsec.service"
    assert category("disk:/") == "disk"
    assert category("gateway:WAN") == "gateway"
    assert category("ipsec.tunnel_ping:site-a/10.0.5.0/24") == "ipsec.tunnel_ping"
    # IPv6 selector keeps only the first colon as the split point
    assert category("ipsec.tunnel_ping:site-a/2001:db8::/64") == "ipsec.tunnel_ping"
    assert category("availability") == "availability"


def test_all_check_categories_listed() -> None:
    # INVARIANT: must match every category the export can emit (the evaluate_checks
    # families plus the overlay services agent/ping/http). valid_selector relies on it.
    assert set(CHECK_CATEGORIES) == {
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


def test_consumers_are_checkmk_plus_three_channels() -> None:
    assert CONSUMERS == (CHECKMK, "mattermost", "telegram", "email")
    assert set(CHANNELS) == {"mattermost", "telegram", "email"}


def test_categories_for_consumer() -> None:
    # Checkmk has no availability node (not exported); channels lead with it.
    assert categories_for(CHECKMK) == CHECK_CATEGORIES
    assert AVAILABILITY not in categories_for(CHECKMK)
    assert categories_for("telegram")[0] == AVAILABILITY
    assert set(categories_for("telegram")) == {AVAILABILITY, *CHECK_CATEGORIES}


# --- Base default OFF ----------------------------------------------------------


def test_no_rules_selects_nothing() -> None:
    assert is_on(CHECKMK, "cpu", 1, []) is False
    assert resolve(CHECKMK, "gateway:WAN", 1, []) == (False, "default")
    assert is_on("telegram", "availability", 1, []) is False


# --- Include turns on ----------------------------------------------------------


def test_global_category_include() -> None:
    # A category selector (no colon) matches every check key in that family.
    rules = [(CHECKMK, None, "gateway", "include")]
    assert resolve(CHECKMK, "gateway:WAN", 1, rules) == (True, "global_category")
    assert is_on(CHECKMK, "gateway:LAN", 99, rules)  # global → any instance, any key
    assert not is_on(CHECKMK, "cpu", 1, rules)
    # A different consumer is unaffected (consumer-scoped).
    assert not is_on("telegram", "gateway:WAN", 1, rules)


def test_categoryless_key_matches_as_specific() -> None:
    # For a check with no colon (memory, cpu, …) selector == key == category, so a
    # global include resolves via the specific path (reason "global"), still on.
    rules = [(CHECKMK, None, "cpu", "include")]
    assert resolve(CHECKMK, "cpu", 1, rules) == (True, "global")
    assert is_on(CHECKMK, "cpu", 99, rules)


def test_instance_specific_include_adds_one_service() -> None:
    rules = [("telegram", 5, "gateway:WAN", "include")]
    assert resolve("telegram", "gateway:WAN", 5, rules) == (True, "instance")
    assert not is_on("telegram", "gateway:WAN", 6, rules)  # other instance off
    assert not is_on("telegram", "gateway:LAN", 5, rules)  # other service off


# --- The headline feature: exclude overrides an included category --------------


def test_instance_exclude_mutes_one_service_under_included_category() -> None:
    rules = [
        (CHECKMK, None, "gateway", "include"),  # whole category on, everywhere
        (CHECKMK, 1, "gateway:WAN", "exclude"),  # but mute WAN on instance 1
    ]
    assert resolve(CHECKMK, "gateway:WAN", 1, rules) == (False, "instance")  # muted
    assert is_on(CHECKMK, "gateway:LAN", 1, rules)  # sibling still on
    assert is_on(CHECKMK, "gateway:WAN", 2, rules)  # other instance still on


def test_global_specific_include_under_excluded_default_is_irrelevant_but_works() -> None:
    # Default is off; a global specific include adds exactly one service.
    rules = [(CHECKMK, None, "ipsec.tunnel_ping:site-a/10.0.5.0/24", "include")]
    assert is_on(CHECKMK, "ipsec.tunnel_ping:site-a/10.0.5.0/24", 3, rules)
    assert not is_on(CHECKMK, "ipsec.tunnel_ping:site-b/10.0.6.0/24", 3, rules)


# --- Precedence ----------------------------------------------------------------


def test_specific_beats_category_same_scope() -> None:
    rules = [(CHECKMK, None, "gateway", "include"), (CHECKMK, None, "gateway:WAN", "exclude")]
    assert resolve(CHECKMK, "gateway:WAN", 1, rules) == (False, "global")
    assert is_on(CHECKMK, "gateway:LAN", 1, rules)


def test_instance_beats_global() -> None:
    # Global include cpu, but instance 2 explicitly excludes it.
    rules = [(CHECKMK, None, "cpu", "include"), (CHECKMK, 2, "cpu", "exclude")]
    assert is_on(CHECKMK, "cpu", 1, rules)  # other box on via global
    assert not is_on(CHECKMK, "cpu", 2, rules)  # box 2 overridden off


def test_instance_category_beats_global_specific() -> None:
    # Global excludes one service, but instance 2 includes its whole category →
    # instance-category (rank 3) beats global-specific (rank 2).
    rules = [
        (CHECKMK, None, "gateway:WAN", "exclude"),
        (CHECKMK, 2, "gateway", "include"),
    ]
    assert is_on(CHECKMK, "gateway:WAN", 2, rules)
    assert not is_on(CHECKMK, "gateway:WAN", 9, rules)  # only global rule applies


def test_resolution_independent_of_rule_order() -> None:
    a = [(CHECKMK, None, "swap", "include"), (CHECKMK, 5, "swap", "exclude")]
    b = list(reversed(a))
    assert is_on(CHECKMK, "swap", 5, a) is False
    assert is_on(CHECKMK, "swap", 5, b) is False


# --- Validators ----------------------------------------------------------------


def test_validators() -> None:
    assert valid_consumer("checkmk") and valid_consumer("email")
    assert not valid_consumer("ntfy")
    assert valid_mode("include") and valid_mode("exclude")
    assert not valid_mode("maybe")
    # selector validity = its category is one this consumer offers
    assert valid_selector(CHECKMK, "gateway:WAN") and valid_selector(CHECKMK, "cpu")
    assert valid_selector("telegram", "availability")
    assert not valid_selector(CHECKMK, "availability")  # not exported
    assert not valid_selector(CHECKMK, "bogus:thing")
