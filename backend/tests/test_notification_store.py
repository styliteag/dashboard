"""Tests for the notification-routes process cache (``is_subscribed_live``).

The cache is a module-level set of ``(instance_id, channel, category, enabled)``
tuples; the hot dispatch path reads it with no DB round-trip. These poke the cache
directly (same style as ``test_settings`` with ``store._overrides``) to assert the
override read — a per-instance route wins over the global one.
"""

from __future__ import annotations

import app.notifications.store as store


def _with_routes(*routes: tuple[int | None, str, str, bool]):
    store._routes.clear()
    store._routes.update(routes)


def test_global_route_is_live_for_every_instance() -> None:
    try:
        _with_routes((None, "mattermost", "availability", True))
        assert store.is_subscribed_live("mattermost", "availability", 1) is True
        assert store.is_subscribed_live("mattermost", "availability", 42) is True
        assert store.is_subscribed_live("telegram", "availability", 1) is False
    finally:
        store._routes.clear()


def test_instance_route_is_live_only_for_its_instance() -> None:
    try:
        _with_routes((7, "telegram", "cert", True))
        assert store.is_subscribed_live("telegram", "cert", 7) is True
        assert store.is_subscribed_live("telegram", "cert", 8) is False
    finally:
        store._routes.clear()


def test_global_and_instance_routes_add_live() -> None:
    try:
        _with_routes((None, "email", "cpu", True), (3, "email", "disk", True))
        assert store.is_subscribed_live("email", "cpu", 3) is True  # via global
        assert store.is_subscribed_live("email", "cpu", 9) is True  # via global
        assert store.is_subscribed_live("email", "disk", 3) is True  # via instance
        assert store.is_subscribed_live("email", "disk", 9) is False  # neither
    finally:
        store._routes.clear()


def test_instance_off_override_suppresses_global_live() -> None:
    try:
        _with_routes((None, "email", "cpu", True), (3, "email", "cpu", False))
        assert store.is_subscribed_live("email", "cpu", 3) is False  # box 3: overridden off
        assert store.is_subscribed_live("email", "cpu", 9) is True  # other box: still on
    finally:
        store._routes.clear()
