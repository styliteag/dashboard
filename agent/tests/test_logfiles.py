"""Tests for the hourly logfile collector (collect_logfiles)."""

from __future__ import annotations

import orbit_agent as agent


def _reset() -> None:
    # -1.0 = collect-NOW sentinel; 0.0 would trigger the fresh-start jitter.
    agent._last_log_ts[0] = -1.0


def test_collects_then_gates_hourly(monkeypatch) -> None:
    _reset()
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent.os.path, "exists", lambda p: True)
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "LOGDATA")

    first = agent.collect_logfiles()
    assert first
    assert all(e.get("name") and e.get("content") == "LOGDATA" for e in first)
    # A second call within the hour must not re-collect.
    assert agent.collect_logfiles() == []


def test_total_cap_respected(monkeypatch) -> None:
    _reset()
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent.os.path, "exists", lambda p: True)
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "x" * agent._LOG_PER_FILE)

    out = agent.collect_logfiles()
    assert sum(len(e["content"]) for e in out) <= agent._LOG_TOTAL_CAP


def test_bad_source_does_not_break_collection(monkeypatch) -> None:
    _reset()
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent.os.path, "exists", lambda p: True)
    calls = {"n": 0}

    def flaky(cmd, timeout=5):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("rotated away")
        return "OK"

    monkeypatch.setattr(agent, "_run", flaky)
    out = agent.collect_logfiles()
    # The first source raised; the remaining ones were still collected.
    assert out and all(e["content"] == "OK" for e in out)


def test_collects_rules_and_dhcp(monkeypatch) -> None:
    _reset()
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent.os.path, "exists", lambda p: True)
    monkeypatch.setattr(agent, "_newest_log", lambda pattern: "/tmp/x.log")  # dhcp path probe
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "DATA")
    names = {e["name"] for e in agent.collect_logfiles()}
    assert "rules" in names and "dhcp" in names


def test_fresh_start_jitters_first_collection(monkeypatch) -> None:
    """Fleet de-sync: after update-all every agent restarts at once; without
    jitter every hourly log push lands in the same minute forever (prod
    slow_push clusters, 2026-07-11)."""
    agent._last_log_ts[0] = 0.0
    clock = [10_000.0]
    monkeypatch.setattr(agent.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(agent.random, "uniform", lambda a, b: 300.0)
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent.os.path, "exists", lambda p: True)
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "LOGDATA")

    assert agent.collect_logfiles() == []  # start: gate armed with jitter
    clock[0] += 299.0
    assert agent.collect_logfiles() == []  # still inside the jitter window
    clock[0] += 2.0
    assert agent.collect_logfiles()  # jitter elapsed → collects
    _reset()


def test_refresh_marker_collects_immediately(monkeypatch) -> None:
    """refresh.full must bypass the jitter — operators expect logs NOW."""
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent.os.path, "exists", lambda p: True)
    monkeypatch.setattr(agent, "_run", lambda *a, **k: "LOGDATA")
    agent._last_log_ts[0] = -1.0
    assert agent.collect_logfiles()
    _reset()
