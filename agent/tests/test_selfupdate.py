"""Tests for the agent self-update primitives (DR-5).

The deterministic parts (verify, stage/swap, rollback, probation cleanup) are
unit-tested here. The restart + supervisor rollback are integration-tested live
on a real box with the operator present.
"""

from __future__ import annotations

import hashlib

import opnsense_agent as agent
import pytest


def test_verify_accepts_matching_sha_and_valid_syntax() -> None:
    code = b"x = 1\n"
    assert agent._verify_update_code(code, hashlib.sha256(code).hexdigest()) is True


def test_verify_rejects_bad_sha() -> None:
    assert agent._verify_update_code(b"x = 1\n", "deadbeef") is False


def test_verify_rejects_syntax_error() -> None:
    code = b"def (:\n"  # not valid Python
    assert agent._verify_update_code(code, hashlib.sha256(code).hexdigest()) is False


def test_apply_and_rollback(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "opnsense_agent.py"
    target.write_bytes(b"OLD VERSION\n")
    monkeypatch.setenv("AGENT_SELF_PATH", str(target))

    agent._apply_update(b"NEW VERSION\n", "9.9.9")
    assert target.read_bytes() == b"NEW VERSION\n"
    assert (tmp_path / "opnsense_agent.py.bak").read_bytes() == b"OLD VERSION\n"
    assert (tmp_path / "opnsense_agent.py.updating").read_text() == "9.9.9"
    assert not (tmp_path / "opnsense_agent.py.new").exists()  # temp consumed by rename

    assert agent._rollback() is True
    assert target.read_bytes() == b"OLD VERSION\n"
    assert not (tmp_path / "opnsense_agent.py.updating").exists()


def test_clear_probation_removes_marker_and_backup(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "opnsense_agent.py"
    target.write_bytes(b"X\n")
    monkeypatch.setenv("AGENT_SELF_PATH", str(target))
    (tmp_path / "opnsense_agent.py.bak").write_bytes(b"OLD\n")
    (tmp_path / "opnsense_agent.py.updating").write_text("1.0")

    agent._clear_probation()
    assert not (tmp_path / "opnsense_agent.py.bak").exists()
    assert not (tmp_path / "opnsense_agent.py.updating").exists()


def test_rollback_without_backup_returns_false(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "opnsense_agent.py"
    target.write_bytes(b"X\n")
    monkeypatch.setenv("AGENT_SELF_PATH", str(target))
    assert agent._rollback() is False
