"""Tests for slug resolution in the instance service (uniqueness + conflict policy).

DB-free: ``_slug_taken`` is monkeypatched with a set so the auto-suffix vs. explicit-
conflict branches are exercised without MariaDB.
"""

from __future__ import annotations

import pytest

import app.instances.service as svc
from app.instances.schemas import InstanceCreate, InstanceUpdate


def _taken(slugs: set[str]):
    async def _inner(session, slug: str, exclude_id) -> bool:  # noqa: ANN001
        return slug in slugs

    return _inner


async def test_derived_slug_auto_suffixes_on_clash(monkeypatch) -> None:
    monkeypatch.setattr(svc, "_slug_taken", _taken({"opn1"}))
    assert await svc._resolve_slug(None, "opn1", auto_suffix=True) == "opn1-2"


async def test_derived_slug_skips_taken_suffixes(monkeypatch) -> None:
    monkeypatch.setattr(svc, "_slug_taken", _taken({"opn1", "opn1-2", "opn1-3"}))
    assert await svc._resolve_slug(None, "opn1", auto_suffix=True) == "opn1-4"


async def test_name_is_slugified_before_lookup(monkeypatch) -> None:
    monkeypatch.setattr(svc, "_slug_taken", _taken(set()))
    out = await svc._resolve_slug(None, "Firewall Büro Süd", auto_suffix=True)
    assert out == "firewall-buero-sued"


async def test_explicit_slug_conflict_raises(monkeypatch) -> None:
    monkeypatch.setattr(svc, "_slug_taken", _taken({"opn1"}))
    with pytest.raises(svc.SlugConflictError):
        await svc._resolve_slug(None, "opn1", auto_suffix=False)


async def test_explicit_slug_free_is_returned(monkeypatch) -> None:
    monkeypatch.setattr(svc, "_slug_taken", _taken({"other"}))
    assert await svc._resolve_slug(None, "opn1", auto_suffix=False) == "opn1"


# --- schema-level validation (no DB) -----------------------------------------


def test_schema_accepts_valid_slug() -> None:
    assert InstanceCreate(name="fw", slug="opn1-bz", base_url="https://a.example").slug == "opn1-bz"


def test_schema_rejects_uppercase_slug() -> None:
    with pytest.raises(ValueError):
        InstanceCreate(name="fw", slug="OPN1", base_url="https://a.example")


def test_schema_rejects_underscore_slug() -> None:
    with pytest.raises(ValueError):
        InstanceUpdate(slug="opn_1")


def test_schema_slug_optional() -> None:
    assert InstanceCreate(name="fw", base_url="https://a.example").slug is None
