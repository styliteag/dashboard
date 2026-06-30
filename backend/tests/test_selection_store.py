"""Tests for the selection process cache (``is_on_live``).

The cache is a module-level set of ``(consumer, instance_id, selector, mode)``
tuples; the dispatch hot path reads it with no DB round-trip. These poke the cache
directly (same style as ``test_settings`` with ``store._overrides``) to assert the
resolution read — default off, include on, instance/specific override.
"""

from __future__ import annotations

import app.selection.store as store


def _with_rules(*rules: tuple[str, int | None, str, str]) -> None:
    store._rules.clear()
    store._rules.update(rules)


def test_default_off_for_everything() -> None:
    try:
        _with_rules()
        assert store.is_on_live("telegram", "availability", 1) is False
        assert store.is_on_live("checkmk", "cpu", 1) is False
    finally:
        store._rules.clear()


def test_global_include_is_live_for_every_instance() -> None:
    try:
        _with_rules(("mattermost", None, "availability", "include"))
        assert store.is_on_live("mattermost", "availability", 1) is True
        assert store.is_on_live("mattermost", "availability", 42) is True
        assert store.is_on_live("telegram", "availability", 1) is False  # other channel off
    finally:
        store._rules.clear()


def test_instance_include_is_live_only_for_its_instance() -> None:
    try:
        _with_rules(("telegram", 7, "cert", "include"))
        assert store.is_on_live("telegram", "cert", 7) is True
        assert store.is_on_live("telegram", "cert", 8) is False
    finally:
        store._rules.clear()


def test_instance_exclude_overrides_global_include_live() -> None:
    try:
        _with_rules(
            ("email", None, "cpu", "include"),
            ("email", 3, "cpu", "exclude"),
        )
        assert store.is_on_live("email", "cpu", 3) is False  # box 3: muted
        assert store.is_on_live("email", "cpu", 9) is True  # other box: still on
    finally:
        store._rules.clear()
