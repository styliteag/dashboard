"""Firmware-check robustness on firewalls (opn1 post-26.7 incident, 2026-07-16).

After the 26.7 series upgrade, pkg needed a minutes-long catalogue rebuild
("wrong packagesite"). The agent's 60s _run timeout killed pkg mid-rebuild and
left repos/OPNsense/{lock,db-journal} behind; every later pkg run (GUI check
included) waited forever on the dead holder while unserialised agent checks
kept stacking — a 16-process convoy. The dashboard pinned "Check failed" for
the 12h window because the retry shortening only existed on linux.
"""

from __future__ import annotations

import threading
import time as _time

import orbit_agent as agent


def _reset_state() -> None:
    agent._STATE.fw_verdict = {}
    agent._STATE.fw_check_ts = 0.0


def test_firewall_check_failed_retries_early(monkeypatch) -> None:
    """check_failed on a firewall must re-arm within _FW_FAILED_RETRY_S, not 12h."""
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.7")
    monkeypatch.setattr(agent, "_opnsense_series", lambda: "26.7")
    monkeypatch.setattr(
        agent, "_opnsense_update_check", lambda v: (False, v, "update check failed", True, "")
    )
    fw = agent.collect_firmware()
    assert fw["check_failed"] is True
    remaining = agent._FW_CHECK_INTERVAL_S - (_time.monotonic() - agent._STATE.fw_check_ts)
    assert remaining <= agent._FW_FAILED_RETRY_S + 5
    _reset_state()


def test_firewall_checks_serialize_and_second_caller_uses_fresh_cache(monkeypatch) -> None:
    """Concurrent collect_firmware callers (push loop + refresh.full) must not
    stack pkg invocations: the lock serializes them and the double-checked
    cache means the waiters reuse the fresh verdict instead of re-checking."""
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.1.11_10")
    monkeypatch.setattr(agent, "_opnsense_series", lambda: "26.1")
    active: list = []
    overlaps: list = []
    calls: list = []

    def slow_check(v):
        calls.append(1)
        active.append(1)
        if len(active) > 1:
            overlaps.append(1)
        _time.sleep(0.05)
        active.pop()
        return False, v, "up to date", False, ""

    monkeypatch.setattr(agent, "_opnsense_update_check", slow_check)
    threads = [threading.Thread(target=agent.collect_firmware) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert overlaps == []
    assert len(calls) == 1, "waiters must reuse the fresh verdict, not re-check"
    _reset_state()


def test_check_skipped_while_vendor_updater_runs(monkeypatch) -> None:
    """While launcher.sh update/upgrade (or pfSense-upgrade -y) is applying,
    collect_firmware must NOT run its own pkg round-trip: it would fight the
    updater for the pkg lock and stall the push loop for minutes — the hub
    then fires "agent silent for >120s" (live on opn2 mid-26.7 pkg phase).
    The neutral verdict must not be cached either."""
    _reset_state()
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.7")
    monkeypatch.setattr(agent, "_vendor_updater_running", lambda plat: True)

    def boom(v):
        raise AssertionError("network check must be skipped while the updater runs")

    monkeypatch.setattr(agent, "_opnsense_update_check", boom)
    fw = agent.collect_firmware()
    assert fw["update_check_output"] == "vendor update in progress"
    assert fw["upgrade_available"] is False
    assert fw["check_failed"] is False
    assert agent._STATE.fw_verdict == {}, "neutral verdict must not be cached"
    _reset_state()


def test_stale_repo_lock_cleared_only_without_live_pkg(monkeypatch, tmp_path) -> None:
    lock = tmp_path / "lock"
    journal = tmp_path / "db-journal"
    monkeypatch.setattr(agent, "_OPNSENSE_REPO_CACHE_DIR", str(tmp_path))

    # A live pkg process → never yank its lock.
    lock.write_text("")
    journal.write_text("")
    monkeypatch.setattr(agent, "_run", lambda cmd, timeout=5: "1234\n")
    assert agent._clear_stale_pkg_repo_lock() is False
    assert lock.exists() and journal.exists()

    # No pkg process → dead holder's leftovers are removed.
    monkeypatch.setattr(agent, "_run", lambda cmd, timeout=5: "")
    assert agent._clear_stale_pkg_repo_lock() is True
    assert not lock.exists() and not journal.exists()


def test_opnsense_check_failure_triggers_lock_cleanup(monkeypatch) -> None:
    """The check_failed path must attempt the stale-lock self-heal so the
    15-min retry can succeed instead of queueing behind a dead holder."""
    cleaned: list = []
    monkeypatch.setattr(agent, "_clear_stale_pkg_repo_lock", lambda: cleaned.append(1))
    monkeypatch.setattr(
        agent, "_run", lambda cmd, timeout=5: ""  # -c empty, pkg update/query/rquery empty
    )
    upgrade, latest, out, failed, _major = agent._opnsense_update_check("26.7")
    assert failed is True
    assert cleaned, "stale-lock cleanup not attempted on failed check"


def test_pkg_catalogue_refresh_timeout_survives_post_major_rebuild(monkeypatch) -> None:
    """`pkg update` gets >=300s: the post-major DB re-create takes minutes and
    a 60s kill mid-rebuild is what wedged opn1 (dead lock holder)."""
    timeouts: dict = {}

    def fake_run(cmd, timeout=5):
        if cmd[:2] == ["pkg", "update"]:
            timeouts["update"] = timeout
        return "26.7\n" if cmd[0] == "pkg" else ""

    monkeypatch.setattr(agent, "_run", fake_run)
    agent._opnsense_update_check("26.7")
    assert timeouts["update"] >= 300
