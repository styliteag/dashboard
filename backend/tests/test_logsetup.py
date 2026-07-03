"""Tests for the unified logging pipeline (structlog + stdlib through one handler).

Format/level assertions capture stdout via capsys — ``structlog.testing.capture_logs``
would swap the processor chain and bypass both level filtering and the handler.
``configure_logging`` is called inside each test so the handler binds pytest's
captured ``sys.stdout``.
"""

from __future__ import annotations

import json
import logging

import structlog

from app.logsetup import configure_logging


def _lines(capsys) -> list[str]:
    return [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]


def test_console_format_renders_key_value(capsys) -> None:
    configure_logging("info", "console")
    structlog.get_logger("app.test").info("my.event", foo="bar")
    out = _lines(capsys)
    assert len(out) == 1
    assert "my.event" in out[0]
    assert "foo=bar" in out[0]
    # capsys stdout is not a tty → colors must be off.
    assert "\x1b[" not in out[0]


def test_json_format_emits_parseable_lines(capsys) -> None:
    configure_logging("info", "json")
    structlog.get_logger("app.test").info("my.event", foo="bar")
    out = _lines(capsys)
    assert len(out) == 1
    doc = json.loads(out[0])
    assert doc["event"] == "my.event"
    assert doc["level"] == "info"
    assert doc["logger"] == "app.test"
    assert doc["foo"] == "bar"
    assert "timestamp" in doc


def test_audit_stream_visible_at_global_warning(capsys) -> None:
    configure_logging("warning", "console")
    structlog.get_logger("app.audit").info("auth.login", result="ok")
    structlog.get_logger("app.other").info("suppressed.event")
    out = _lines(capsys)
    assert len(out) == 1
    assert "auth.login" in out[0]


def test_reconfigure_does_not_duplicate_handlers(capsys) -> None:
    configure_logging("info", "console")
    configure_logging("info", "console")
    structlog.get_logger("app.test").info("once.only")
    out = _lines(capsys)
    assert len(out) == 1


def test_foreign_stdlib_record_uses_same_pipeline(capsys) -> None:
    configure_logging("info", "json")
    logging.getLogger("uvicorn.error").info("Uvicorn running on http://127.0.0.1:8000")
    out = _lines(capsys)
    assert len(out) == 1
    doc = json.loads(out[0])
    assert doc["event"] == "Uvicorn running on http://127.0.0.1:8000"
    assert doc["logger"] == "uvicorn.error"


def test_uvicorn_access_is_silenced(capsys) -> None:
    configure_logging("info", "console")
    logging.getLogger("uvicorn.access").info('127.0.0.1:0 - "GET / HTTP/1.0" 200')
    assert _lines(capsys) == []


def test_noisy_libraries_are_quieted(capsys) -> None:
    configure_logging("debug", "console")
    logging.getLogger("apscheduler.executors.default").info("Job executed successfully")
    logging.getLogger("httpcore.http11").debug("send_request_body.started")
    logging.getLogger("httpx").info("HTTP Request: POST ...")
    logging.getLogger("asyncssh").info("[conn=0] Auth for user root succeeded")
    assert _lines(capsys) == []
    logging.getLogger("apscheduler.executors.default").warning("job overran")
    assert len(_lines(capsys)) == 1


def test_uvicorn_debug_frame_traces_suppressed_at_debug(capsys) -> None:
    # The websockets library logs per-frame traces (< TEXT, > PING) at DEBUG on
    # the uvicorn.error logger — never useful in docker logs, even at level=debug.
    configure_logging("debug", "console")
    logging.getLogger("uvicorn.error").debug("> PING 4e 47 50 96 [binary, 4 bytes]")
    assert _lines(capsys) == []
    structlog.get_logger("app.test").debug("app.debug_visible")
    assert len(_lines(capsys)) == 1


def test_uvicorn_loggers_inherit_root_level(capsys) -> None:
    # uvicorn sets INFO explicitly on its loggers at process start; an explicit
    # level would beat the root level and leak "connection open" at warning.
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    configure_logging("warning", "console")
    logging.getLogger("uvicorn.error").info("connection open")
    assert _lines(capsys) == []
