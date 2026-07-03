"""Tests for the editable-settings store: coercion, override precedence, routes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException, Request

import app.settings.store as store
from app.config import get_settings
from app.settings.registry import EDITABLE, coerce_value
from app.settings.routes import SettingUpdate, update_setting
from app.settings.store import effective_settings


def test_coerce_int_range() -> None:
    d = EDITABLE["poll_interval_seconds"]  # min 5
    assert coerce_value(d, "30") == 30
    with pytest.raises(ValueError):
        coerce_value(d, "abc")
    with pytest.raises(ValueError):
        coerce_value(d, "1")  # below min


def test_coerce_log_level_options() -> None:
    d = EDITABLE["log_level"]
    assert coerce_value(d, "debug") == "debug"
    with pytest.raises(ValueError):
        coerce_value(d, "trace")


def test_effective_override_precedence() -> None:
    store._overrides.clear()
    try:
        base = get_settings()
        # No override → env default.
        assert effective_settings().poll_interval_seconds == base.poll_interval_seconds
        # Override wins and is coerced to int.
        store._overrides["poll_interval_seconds"] = "99"
        eff = effective_settings()
        assert eff.poll_interval_seconds == 99
        assert isinstance(eff.poll_interval_seconds, int)
        # A non-overridden editable key still reads the env default.
        assert eff.metrics_retention_days == base.metrics_retention_days
        # A non-editable attribute delegates to the base settings.
        assert eff.env == base.env
    finally:
        store._overrides.clear()


def _put_request() -> Request:
    return Request({"type": "http", "method": "PUT", "headers": []})


@pytest.mark.asyncio
async def test_update_unknown_key_404() -> None:
    with pytest.raises(HTTPException) as exc:
        await update_setting(
            SettingUpdate(key="not_a_setting", value="1"),
            _put_request(),
            session=None,  # type: ignore[arg-type]  - unreached on 404
            admin=SimpleNamespace(id=1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_update_invalid_value_422() -> None:
    # Validation happens before any DB access, so the session is never touched.
    with pytest.raises(HTTPException) as exc:
        await update_setting(
            SettingUpdate(key="poll_interval_seconds", value="abc"),
            _put_request(),
            session=None,  # type: ignore[arg-type]
            admin=SimpleNamespace(id=1),  # type: ignore[arg-type]
        )
    assert exc.value.status_code == 422


def test_coerce_log_format_options() -> None:
    d = EDITABLE["log_format"]
    assert coerce_value(d, "console") == "console"
    assert coerce_value(d, "json") == "json"
    with pytest.raises(ValueError):
        coerce_value(d, "xml")
    assert d.restart_required is True
    assert get_settings().log_format == "console"
