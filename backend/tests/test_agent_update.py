"""Tests for the served-agent-version parser used by the self-update endpoint."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.agent_hub import routes


def test_iso_utc_tags_naive_as_utc() -> None:
    # MariaDB returns naive datetimes (still UTC) → must gain a +00:00 offset so
    # the browser doesn't render them as local time.
    naive = datetime(2026, 6, 24, 6, 22, 54)
    assert routes._iso_utc(naive) == "2026-06-24T06:22:54+00:00"


def test_iso_utc_preserves_aware() -> None:
    aware = datetime(2026, 6, 24, 6, 22, 54, tzinfo=UTC)
    assert routes._iso_utc(aware) == "2026-06-24T06:22:54+00:00"


def test_iso_utc_none() -> None:
    assert routes._iso_utc(None) is None


def test_served_agent_version_parses(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "opnsense_agent.py").write_text(
        '#!/usr/bin/env python3\n__version__ = "1.2.3"\n\nx = 1\n'
    )
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)
    assert routes._served_agent_version() == "1.2.3"


def test_served_agent_version_single_quotes(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "opnsense_agent.py").write_text("__version__ = '0.3.0'\n")
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)
    assert routes._served_agent_version() == "0.3.0"


def test_served_agent_version_missing_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)
    assert routes._served_agent_version() is None


def test_agent_update_params(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    import base64
    import hashlib

    src = tmp_path / "opnsense_agent.py"
    src.write_text('__version__ = "1.2.3"\nx = 1\n')
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)

    params = routes._agent_update_params()
    assert params is not None
    assert params["version"] == "1.2.3"
    assert params["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    assert base64.b64decode(params["code"]) == src.read_bytes()


def test_agent_update_params_missing_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "_AGENT_DIR", tmp_path)
    assert routes._agent_update_params() is None
