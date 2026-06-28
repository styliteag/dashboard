"""Tests for the per-channel notification routing (pure, DB-free)."""

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
    routes = {("mattermost", "availability"), ("email", "cert")}
    assert is_subscribed("mattermost", "availability", routes) is True
    assert is_subscribed("email", "cert", routes) is True
    assert is_subscribed("mattermost", "cert", routes) is False  # category not subscribed
    assert is_subscribed("telegram", "availability", routes) is False  # channel not subscribed


def test_is_subscribed_accepts_any_iterable() -> None:
    routes = [("telegram", "cpu")]  # a list, not a set
    assert is_subscribed("telegram", "cpu", routes) is True


def test_validators() -> None:
    assert valid_channel("email") and not valid_channel("ntfy")
    assert valid_category("availability") and valid_category("cert")
    assert not valid_category("nonsense")
