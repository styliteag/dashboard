"""Tests for the audit→log bridge: every write_audit also emits an app.audit event."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from structlog.testing import capture_logs

from app.audit.log import write_audit


def _session() -> MagicMock:
    session = MagicMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    return session


@pytest.mark.asyncio
async def test_ok_result_logs_info() -> None:
    with capture_logs() as cap:
        await write_audit(
            _session(), action="auth.login", result="ok", user_id=1, source_ip="1.2.3.4"
        )
    (event,) = cap
    assert event["event"] == "auth.login"
    assert event["log_level"] == "info"
    assert event["result"] == "ok"
    assert event["user_id"] == 1
    assert event["ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_denied_and_error_log_warning() -> None:
    with capture_logs() as cap:
        await write_audit(_session(), action="auth.login", result="denied")
        await write_audit(_session(), action="auth.login", result="error")
        await write_audit(_session(), action="auth.login", result="pending")
    assert [e["log_level"] for e in cap] == ["warning", "warning", "info"]


@pytest.mark.asyncio
async def test_detail_is_whitelisted() -> None:
    with capture_logs() as cap:
        await write_audit(
            _session(),
            action="settings.update",
            result="ok",
            detail={"reason": "why", "value": "SECRET", "nested": {"x": 1}},
        )
    (event,) = cap
    assert event["reason"] == "why"
    assert "value" not in event
    assert "nested" not in event


@pytest.mark.asyncio
async def test_target_is_combined() -> None:
    with capture_logs() as cap:
        await write_audit(
            _session(), action="instance.delete", result="ok", target_type="instance", target_id=7
        )
    (event,) = cap
    assert event["target"] == "instance:7"


@pytest.mark.asyncio
async def test_lock_triggered_emits_ip_blocked() -> None:
    with capture_logs() as cap:
        await write_audit(
            _session(),
            action="auth.login",
            result="error",
            source_ip="9.9.9.9",
            detail={"reason": "bad_credentials", "username": "admin", "lock_triggered": True},
        )
    events = {e["event"]: e for e in cap}
    assert events["auth.login"]["log_level"] == "warning"
    blocked = events["auth.ip_blocked"]
    assert blocked["log_level"] == "warning"
    assert blocked["ip"] == "9.9.9.9"
    assert blocked["username"] == "admin"
