"""firmware.upgrade_status on OPNsense/pfSense (live progress + verdict re-arm).

Regression for the 2026-07-15 opn1 incident: a pkg-only point release
(26.1.11_5 -> _10, no reboot) left the UI on "Tracking progress..." forever
(upgrade_status answered "unknown" on firewalls) and the 12h-cached verdict
kept advertising "1 available" although the box was already up to date.
"""

from __future__ import annotations

import time

import orbit_agent as agent


def _reset_state() -> None:
    agent._STATE.fw_verdict = {}
    agent._STATE.fw_check_ts = 0.0
    agent._STATE.fw_update_ts = 0.0


def _fake_progress(monkeypatch, tmp_path, text: str, exists: bool = True):
    path = tmp_path / "pkg_upgrade.progress"
    if exists:
        path.write_text(text)
    monkeypatch.setattr(agent, "_OPNSENSE_UPGRADE_PROGRESS", str(path))
    monkeypatch.setattr(agent, "_PFSENSE_UPGRADE_LOG", str(path))
    return path


def _fake_pgrep(monkeypatch, running: bool) -> list:
    calls: list = []

    def run(cmd, timeout=5):
        calls.append(cmd)
        return "1234\n" if running else ""

    monkeypatch.setattr(agent, "_run", run)
    return calls


def test_opnsense_running_while_launcher_active(monkeypatch, tmp_path) -> None:
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    _fake_progress(monkeypatch, tmp_path, "Fetching packages...\nInstalling...\n")
    calls = _fake_pgrep(monkeypatch, running=True)
    agent._STATE.fw_update_ts = time.time() - 30

    result = agent._cmd_upgrade_status({})
    assert result["success"] is True and result["status"] == "running"
    assert result["log"][-1] == "Installing..."
    # Pattern must target the update/upgrade run only — launcher.sh also runs
    # unrelated changelog cron jobs that must not read as "running".
    assert any("launcher.sh (update|upgrade)" in " ".join(c) for c in calls)


def test_opnsense_done_marker_reports_done_and_drops_verdict(monkeypatch, tmp_path) -> None:
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    _fake_progress(monkeypatch, tmp_path, "Nothing to do.\nStarting web GUI...done.\n***DONE***\n")
    # Marker beats a still-matching pgrep (launcher tearing down).
    _fake_pgrep(monkeypatch, running=True)
    agent._STATE.fw_update_ts = time.time() - 120
    agent._STATE.fw_verdict = {"upgrade_available": True}
    agent._STATE.fw_check_ts = 999.0

    result = agent._cmd_upgrade_status({})
    assert result["status"] == "done"
    assert "***DONE***" in result["log"][-1]
    # Verdict dropped + throttle re-armed: next push re-checks instead of
    # serving the pre-update "1 available" for up to 12h.
    assert agent._STATE.fw_verdict == {}
    assert agent._STATE.fw_check_ts == 0.0
    assert agent._STATE.fw_update_ts == 0.0


def test_opnsense_stale_previous_progress_is_not_instant_done(monkeypatch, tmp_path) -> None:
    """First poll right after "Start update": the progress file still holds the
    PREVIOUS run's ***DONE*** marker (it survives until reboot). Must report
    running ("waiting for the updater"), never an instant done."""
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    path = _fake_progress(monkeypatch, tmp_path, "old run\n***DONE***\n")
    _fake_pgrep(monkeypatch, running=False)
    # Update triggered AFTER the file was last written.
    agent._STATE.fw_update_ts = path.stat().st_mtime + 10
    monkeypatch.setattr(agent.time, "time", lambda: path.stat().st_mtime + 15)
    agent._STATE.fw_verdict = {"upgrade_available": True}

    result = agent._cmd_upgrade_status({})
    assert result["status"] == "running"
    # Verdict untouched while still waiting.
    assert agent._STATE.fw_verdict == {"upgrade_available": True}
    _reset_state()


def test_idle_poll_without_update_does_not_drop_verdict(monkeypatch, tmp_path) -> None:
    """A stray upgrade_status poll with no update running (fw_update_ts unset)
    must not re-arm the check throttle — that would turn every poll into a
    fresh vendor-repo check on the next push."""
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    _fake_progress(monkeypatch, tmp_path, "old run\n***DONE***\n")
    _fake_pgrep(monkeypatch, running=False)
    agent._STATE.fw_verdict = {"upgrade_available": False}
    agent._STATE.fw_check_ts = 999.0

    result = agent._cmd_upgrade_status({})
    assert result["status"] == "done"
    assert agent._STATE.fw_verdict == {"upgrade_available": False}
    assert agent._STATE.fw_check_ts == 999.0
    _reset_state()


def test_pfsense_running_and_done_via_process(monkeypatch, tmp_path) -> None:
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    path = _fake_progress(monkeypatch, tmp_path, ">>> Upgrading packages...\n")
    calls = _fake_pgrep(monkeypatch, running=True)
    agent._STATE.fw_update_ts = path.stat().st_mtime + 1  # fresh-ish trigger

    result = agent._cmd_upgrade_status({})
    assert result["status"] == "running"
    # pgrep pattern must target the -y run, not the periodic `-c` check.
    assert any("pfSense-upgrade -y" in " ".join(c) for c in calls)

    path.write_text(">>> Upgrading packages...\nYour system is up to date\n")
    _fake_pgrep(monkeypatch, running=False)
    result = agent._cmd_upgrade_status({})
    assert result["status"] == "done"
    assert result["log"][-1] == "Your system is up to date"
    assert agent._STATE.fw_verdict == {}
    _reset_state()


def test_collect_firmware_drops_verdict_once_advertised_version_installed(monkeypatch) -> None:
    """Bulk "Update all" / manual CLI update: nobody polls upgrade_status and a
    pkg-only release never restarts the agent — collect_firmware itself must
    notice installed == advertised latest and re-check instead of serving the
    stale "1 available" for 12h (opn1 incident 2026-07-15)."""
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.1.11_10")
    monkeypatch.setattr(agent, "_opnsense_series", lambda: "26.1")
    calls: list[int] = []

    def fresh_check(installed):
        calls.append(1)
        return False, "26.1.11_10", "up to date", False

    monkeypatch.setattr(agent, "_opnsense_update_check", fresh_check)
    monkeypatch.setattr(agent.time, "monotonic", lambda: 100.0)
    agent._STATE.fw_verdict = {
        "upgrade_available": True,
        "product_latest": "26.1.11_10",
        "update_check_output": "26.1.11_5 can be updated to 26.1.11_10",
    }
    agent._STATE.fw_check_ts = 99.0  # well inside the 12h window

    result = agent.collect_firmware()
    assert calls, "stale verdict served although the advertised update is installed"
    assert result["upgrade_available"] is False
    _reset_state()


def test_collect_firmware_keeps_verdict_while_update_pending(monkeypatch) -> None:
    """The guard must only fire once the version actually changed — a pending
    update (installed != latest) keeps the cached verdict."""
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.1.11_5")
    monkeypatch.setattr(agent.time, "monotonic", lambda: 100.0)

    def boom(installed):
        raise AssertionError("cached verdict must be served, not re-checked")

    monkeypatch.setattr(agent, "_opnsense_update_check", boom)
    agent._STATE.fw_verdict = {
        "upgrade_available": True,
        "product_latest": "26.1.11_10",
        "update_check_output": "26.1.11_5 can be updated to 26.1.11_10",
    }
    agent._STATE.fw_check_ts = 99.0

    result = agent.collect_firmware()
    assert result["upgrade_available"] is True
    assert result["product_version"] == "26.1.11_5"
    _reset_state()
