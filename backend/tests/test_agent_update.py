"""Tests for the served-agent-version parser used by the self-update endpoint."""

from __future__ import annotations

import pytest

from app.agent_hub import routes


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
