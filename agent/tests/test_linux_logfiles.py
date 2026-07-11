"""Linux log snapshots (§25): journald-first with /var/log fallback."""

from __future__ import annotations

import orbit_agent as agent


def _reset() -> None:
    # -1.0 = collect-NOW sentinel; 0.0 would trigger the fresh-start jitter.
    agent._last_log_ts[0] = -1.0


def test_linux_journald_sources(monkeypatch) -> None:
    _reset()
    calls: list[str] = []

    def fake_run(cmd, timeout=5):
        calls.append(cmd[-1])
        return "LOGDATA"

    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent.shutil, "which", lambda n: "/usr/bin/journalctl")
    monkeypatch.setattr(agent, "_run", fake_run)
    out = agent.collect_logfiles()
    names = [e["name"] for e in out]
    assert names == ["journal-err", "journal-warn", "auth", "dmesg"]
    assert any("-p 3" in c for c in calls)  # err = prio 0..3
    assert any("-p 4..4" in c for c in calls)  # warn only, no double-report
    # Hourly gate applies to the linux branch too.
    assert agent.collect_logfiles() == []
    _reset()


def test_linux_fallback_to_var_log_without_systemd(monkeypatch) -> None:
    _reset()
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent.shutil, "which", lambda n: None)
    monkeypatch.setattr(
        agent.os.path, "exists", lambda p: p in ("/var/log/syslog", "/var/log/auth.log")
    )
    monkeypatch.setattr(agent, "_run", lambda cmd, timeout=5: "LOGDATA")
    names = [e["name"] for e in agent.collect_logfiles()]
    assert names == ["syslog", "auth", "dmesg"]
    _reset()


def test_linux_one_bad_source_never_drops_the_rest(monkeypatch) -> None:
    _reset()
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent.shutil, "which", lambda n: "/usr/bin/journalctl")

    def flaky_run(cmd, timeout=5):
        if "-p 3" in cmd[-1]:
            raise OSError("boom")
        return "LOGDATA"

    monkeypatch.setattr(agent, "_run", flaky_run)
    names = [e["name"] for e in agent.collect_logfiles()]
    assert "journal-err" not in names
    assert "journal-warn" in names and "dmesg" in names
    _reset()
