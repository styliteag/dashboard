"""Dashboard-pinned push cadence (welcome / config_update → live cfg)."""

from __future__ import annotations

import orbit_agent as agent
import pytest


@pytest.fixture
def cfg(monkeypatch):
    c = agent.Config(path="/nonexistent-orbit-test.conf")  # no file → defaults (30s)
    monkeypatch.setattr(agent._STATE, "config", c)
    return c


def test_apply_sets_interval(cfg):
    agent._apply_push_interval(60)
    assert cfg.push_interval == 60


def test_apply_accepts_numeric_string(cfg):
    agent._apply_push_interval("45")
    assert cfg.push_interval == 45


def test_apply_ignores_none(cfg):
    agent._apply_push_interval(None)
    assert cfg.push_interval == 30


def test_apply_ignores_zero_hot_loop_guard(cfg):
    agent._apply_push_interval(0)
    assert cfg.push_interval == 30


def test_apply_ignores_negative(cfg):
    agent._apply_push_interval(-5)
    assert cfg.push_interval == 30


def test_apply_ignores_junk(cfg):
    agent._apply_push_interval("fast")
    assert cfg.push_interval == 30


def test_apply_no_config_is_safe(monkeypatch):
    monkeypatch.setattr(agent._STATE, "config", None)
    agent._apply_push_interval(60)  # must not raise
