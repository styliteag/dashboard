"""Tests for instance slug derivation + validation (GUI-proxy persistent URLs).

The display ``name`` stays free-form; ``slug`` is the URL-safe DNS label used in
the prod GUI-proxy origin ``gui-<slug>.<domain>``. German umlauts transliterate
to ASCII digraphs so names like "Firewall Büro Süd" yield "firewall-buero-sued".
"""

from __future__ import annotations

from app.instances.slug import is_valid_slug, slugify_name


def test_basic_lowercase_and_spaces() -> None:
    assert slugify_name("Firewall Bonn") == "firewall-bonn"


def test_german_umlauts_transliterated() -> None:
    assert slugify_name("Firewall Büro Süd") == "firewall-buero-sued"
    assert slugify_name("Größe Öltank") == "groesse-oeltank"
    assert slugify_name("Straße") == "strasse"


def test_latin_accents_stripped() -> None:
    assert slugify_name("café münchen") == "cafe-muenchen"


def test_collapses_and_strips_separators() -> None:
    assert slugify_name("  a -- b __ c! ") == "a-b-c"


def test_truncated_to_63() -> None:
    s = slugify_name("x" * 100)
    assert len(s) == 63
    assert s == "x" * 63


def test_empty_or_symbol_only_falls_back() -> None:
    assert slugify_name("!!!") == "fw"
    assert slugify_name("   ") == "fw"


def test_no_leading_trailing_hyphen() -> None:
    out = slugify_name("-opn1-")
    assert not out.startswith("-")
    assert not out.endswith("-")
    assert out == "opn1"


def test_is_valid_slug_accepts() -> None:
    assert is_valid_slug("opn1")
    assert is_valid_slug("gui-test-3")
    assert is_valid_slug("a")
    assert is_valid_slug("a" * 63)


def test_is_valid_slug_rejects() -> None:
    assert not is_valid_slug("OPN1")  # uppercase
    assert not is_valid_slug("-opn1")  # leading hyphen
    assert not is_valid_slug("opn1-")  # trailing hyphen
    assert not is_valid_slug("opn_1")  # underscore
    assert not is_valid_slug("opn 1")  # space
    assert not is_valid_slug("")  # empty
    assert not is_valid_slug("a" * 64)  # too long


def test_slugify_output_always_valid() -> None:
    for name in ["Firewall Büro Süd", "!!!", "x" * 100, "A.B.C", "café münchen", "-x-"]:
        assert is_valid_slug(slugify_name(name)), name
