"""Tests for the per-channel notification routing (pure, DB-free).

A route is ``(instance_id, channel, category, enabled)``. ``instance_id`` ``None``
is a *global* route that applies to every instance; a non-NULL value scopes it to
one instance. Matching is **override (precedence)**: a per-instance route wins over
the global one (its ``enabled`` decides), so a global-on category can be switched
off for a single box. With no per-instance route, the global route's presence
decides. Global routes are always ``enabled``.
"""

from __future__ import annotations

from app.checkmk.exclusions import CATEGORIES as CHECK_CATEGORIES
from app.notifications.routing import (
    AVAILABILITY,
    CATEGORIES,
    CHANNELS,
    is_subscribed,
    valid_category,
    valid_channel,
)


def test_channels_are_the_three_configurable_ones() -> None:
    assert set(CHANNELS) == {"mattermost", "telegram", "email"}


def test_categories_are_availability_plus_check_categories() -> None:
    assert CATEGORIES[0] == AVAILABILITY  # availability first (display order)
    assert set(CATEGORIES) == {AVAILABILITY, *CHECK_CATEGORIES}


def test_is_subscribed_matches_channel_and_category() -> None:
    routes = {(None, "mattermost", "availability", True), (None, "email", "cert", True)}
    assert is_subscribed("mattermost", "availability", 1, routes) is True
    assert is_subscribed("email", "cert", 1, routes) is True
    assert is_subscribed("mattermost", "cert", 1, routes) is False  # category not subscribed
    assert is_subscribed("telegram", "availability", 1, routes) is False  # channel not subscribed


def test_is_subscribed_accepts_any_iterable() -> None:
    routes = [(None, "telegram", "cpu", True)]  # a list, not a set
    assert is_subscribed("telegram", "cpu", 5, routes) is True


# --- Override truth table (the spec). ------------------------------------------


def test_global_route_applies_to_the_matching_instance() -> None:
    routes = {(None, "mattermost", "cpu", True)}
    assert is_subscribed("mattermost", "cpu", 1, routes) is True


def test_global_route_applies_to_any_instance_without_an_override() -> None:
    routes = {(None, "mattermost", "cpu", True)}
    assert is_subscribed("mattermost", "cpu", 999, routes) is True


def test_instance_route_applies_only_to_its_instance() -> None:
    routes = {(2, "telegram", "cert", True)}
    assert is_subscribed("telegram", "cert", 2, routes) is True
    assert is_subscribed("telegram", "cert", 3, routes) is False


def test_no_route_means_not_subscribed() -> None:
    assert is_subscribed("email", "gateway", 1, set()) is False


def test_global_and_instance_routes_add() -> None:
    # Global cpu for all + an extra cert route only for instance 2.
    routes = {(None, "mattermost", "cpu", True), (2, "mattermost", "cert", True)}
    assert is_subscribed("mattermost", "cpu", 1, routes) is True  # via global
    assert is_subscribed("mattermost", "cpu", 2, routes) is True  # via global
    assert is_subscribed("mattermost", "cert", 2, routes) is True  # via instance route
    assert is_subscribed("mattermost", "cert", 1, routes) is False  # neither


# --- The new override behaviour: a per-instance route beats the global one. -----


def test_instance_off_override_suppresses_a_global_on() -> None:
    # Global cpu on for all, but explicitly switched OFF for instance 2.
    routes = {(None, "mattermost", "cpu", True), (2, "mattermost", "cpu", False)}
    assert is_subscribed("mattermost", "cpu", 1, routes) is True  # other box: still via global
    assert is_subscribed("mattermost", "cpu", 2, routes) is False  # box 2: overridden off


def test_instance_on_override_with_no_global() -> None:
    # No global route; instance 2 explicitly on. (Same as a plain per-instance add.)
    routes = {(2, "mattermost", "cpu", True)}
    assert is_subscribed("mattermost", "cpu", 2, routes) is True
    assert is_subscribed("mattermost", "cpu", 3, routes) is False


def test_instance_override_wins_regardless_of_route_order() -> None:
    # Iteration order must not change the verdict — the per-instance row always wins.
    on_first = [(None, "email", "swap", True), (5, "email", "swap", False)]
    off_first = [(5, "email", "swap", False), (None, "email", "swap", True)]
    assert is_subscribed("email", "swap", 5, on_first) is False
    assert is_subscribed("email", "swap", 5, off_first) is False


def test_validators() -> None:
    assert valid_channel("email") and not valid_channel("ntfy")
    assert valid_category("availability") and valid_category("cert")
    assert not valid_category("nonsense")
