"""Pre-update ZFS boot environments (orbit-pre-*) around firmware.update.

The vendors create NO snapshot on their own (the 26.7 release notes tell users
to snapshot manually) — the agent does it before starting an update on
FreeBSD root-on-ZFS. Best effort: UFS installs or bectl failures must never
block the update itself.
"""

from __future__ import annotations

from types import SimpleNamespace

import orbit_agent as agent

_LISTING = (
    "default\tNR\t/\t2.13G\t2026-06-20 15:47\n"
    "pre-26.7-upgrade\t-\t-\t8K\t2026-07-16 00:04\n"
)


def _capture_bectl(monkeypatch, listing: str, create_rc: int = 0):
    calls: list[list] = []

    def fake_run(cmd, timeout=5):
        calls.append(list(cmd))
        if cmd[:2] == ["bectl", "list"]:
            return listing
        return ""

    def fake_subprocess_run(cmd, **kw):
        calls.append(list(cmd))
        return SimpleNamespace(returncode=create_rc, stdout="", stderr="")

    monkeypatch.setattr(agent, "_run", fake_run)
    monkeypatch.setattr(agent.subprocess, "run", fake_subprocess_run)
    return calls


def test_snapshot_created_recursively_with_version_name(monkeypatch) -> None:
    # -r is load-bearing on pfSense: /cf (config.xml), var_db_pkg and
    # var_cache_pkg are CHILD datasets of the BE — a non-recursive BE boots
    # into "config.xml is corrupted" (pf2, 2026-07-16). The rollback BE was
    # unusable exactly when it was needed.
    calls = _capture_bectl(monkeypatch, _LISTING)
    name = agent._zfs_boot_snapshot("26.1.11_10")
    assert name == "orbit-pre-26.1.11_10"
    assert ["bectl", "create", "-r", "orbit-pre-26.1.11_10"] in calls


def test_no_zfs_means_no_snapshot_and_no_error(monkeypatch) -> None:
    # UFS install / bectl missing: _run returns "" — update must proceed.
    calls = _capture_bectl(monkeypatch, "")
    assert agent._zfs_boot_snapshot("26.1.11_10") == ""
    assert not any(c[:2] == ["bectl", "create"] for c in calls)


def test_existing_snapshot_is_idempotent(monkeypatch) -> None:
    listing = _LISTING + "orbit-pre-26.1.11_10\t-\t-\t8K\t2026-07-10 10:00\n"
    calls = _capture_bectl(monkeypatch, listing)
    assert agent._zfs_boot_snapshot("26.1.11_10") == "orbit-pre-26.1.11_10"
    assert not any(c[:2] == ["bectl", "create"] for c in calls)


def test_create_failure_returns_empty_but_never_raises(monkeypatch) -> None:
    _capture_bectl(monkeypatch, _LISTING, create_rc=1)
    assert agent._zfs_boot_snapshot("26.1.11_10") == ""


def test_prunes_only_old_orbit_bes_never_user_or_active(monkeypatch) -> None:
    listing = (
        "default\tNR\t/\t2.13G\t2026-06-20 15:47\n"
        "pre-26.7-upgrade\t-\t-\t650M\t2026-07-16 00:04\n"  # user BE — untouchable
        "orbit-pre-26.1.9\t-\t-\t100M\t2026-05-01 10:00\n"  # oldest orbit — doomed
        "orbit-pre-26.1.10\tR\t-\t100M\t2026-06-01 10:00\n"  # active-on-reboot — spared
        "orbit-pre-26.1.11\t-\t-\t100M\t2026-07-01 10:00\n"  # newest old orbit — kept
    )
    calls = _capture_bectl(monkeypatch, listing)
    name = agent._zfs_boot_snapshot("26.1.11_10")
    assert name == "orbit-pre-26.1.11_10"
    destroyed = [c[2] for c in calls if c[:2] == ["bectl", "destroy"]]
    # keep = _BE_KEEP(2) incl. the new one -> one retention slot for old BEs:
    # 26.1.11 (newest) stays, 26.1.10 would go but is active (R), 26.1.9 goes.
    assert "orbit-pre-26.1.9" in destroyed
    assert "orbit-pre-26.1.10" not in destroyed  # active flag protects it
    assert "orbit-pre-26.1.11" not in destroyed
    assert "pre-26.7-upgrade" not in destroyed
    assert "default" not in destroyed


def test_firmware_update_reports_snapshot_note(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.1.11_10")
    monkeypatch.setattr(agent, "_zfs_boot_snapshot", lambda v: "orbit-pre-%s" % v)
    popens: list[list] = []
    monkeypatch.setattr(
        agent.subprocess, "Popen", lambda cmd, **kw: popens.append(list(cmd))
    )
    result = agent._cmd_firmware_update({})
    assert result["success"] is True
    assert "boot environment orbit-pre-26.1.11_10 created" in result["output"]
    assert ["configctl", "firmware", "update"] in popens
    agent._STATE.fw_update_ts = 0.0


def test_firmware_update_proceeds_without_snapshot(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.1.11_10")
    monkeypatch.setattr(agent, "_zfs_boot_snapshot", lambda v: "")
    monkeypatch.setattr(agent.subprocess, "Popen", lambda cmd, **kw: None)
    result = agent._cmd_firmware_update({})
    assert result["success"] is True
    assert result["output"] == "update started in background"
    agent._STATE.fw_update_ts = 0.0
