"""collect_config_backup: push only on real change (mtime gate + sha256 gate)."""

from __future__ import annotations

import base64
import gzip
import hashlib
import os

import orbit_agent as agent


def _reset_state() -> None:
    agent._STATE.config_push_mtime = -1.0
    agent._STATE.config_push_sha = ""


def _write(path, text: str) -> None:
    path.write_text(text)


def test_first_run_pushes_baseline(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "config.xml"
    _write(cfg, "<opnsense>v1</opnsense>")
    monkeypatch.setattr(agent, "_CONFIG_XML", str(cfg))
    _reset_state()

    out = agent.collect_config_backup()
    raw = gzip.decompress(base64.b64decode(out["content_gz_b64"]))
    assert raw == b"<opnsense>v1</opnsense>"
    assert out["sha256"] == hashlib.sha256(raw).hexdigest()
    assert out["size"] == len(raw)


def test_unchanged_mtime_pushes_nothing(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "config.xml"
    _write(cfg, "<opnsense>v1</opnsense>")
    monkeypatch.setattr(agent, "_CONFIG_XML", str(cfg))
    _reset_state()

    assert agent.collect_config_backup() != {}
    assert agent.collect_config_backup() == {}


def test_touch_without_change_pushes_nothing(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "config.xml"
    _write(cfg, "<opnsense>v1</opnsense>")
    monkeypatch.setattr(agent, "_CONFIG_XML", str(cfg))
    _reset_state()

    assert agent.collect_config_backup() != {}
    os.utime(cfg, (1e9, 1e9))  # mtime changes, content identical
    assert agent.collect_config_backup() == {}


def test_content_change_pushes_new_version(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "config.xml"
    _write(cfg, "<opnsense>v1</opnsense>")
    monkeypatch.setattr(agent, "_CONFIG_XML", str(cfg))
    _reset_state()

    first = agent.collect_config_backup()
    _write(cfg, "<opnsense>v2</opnsense>")
    os.utime(cfg, (2e9, 2e9))
    second = agent.collect_config_backup()
    assert second != {}
    assert second["sha256"] != first["sha256"]


def test_missing_file_pushes_nothing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(agent, "_CONFIG_XML", str(tmp_path / "gone.xml"))
    _reset_state()
    assert agent.collect_config_backup() == {}


def test_oversized_file_is_skipped(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "config.xml"
    _write(cfg, "x" * 1024)
    monkeypatch.setattr(agent, "_CONFIG_XML", str(cfg))
    monkeypatch.setattr(agent, "_CONFIG_PUSH_MAX", 100)
    _reset_state()
    assert agent.collect_config_backup() == {}
