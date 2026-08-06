"""pfSense update-branch pin + self-heal after a repoc slot reorder.

Incident (pfplus1, Netgate ARM64, 2026-08-06): the dashboard series upgrade
Plus 25.07.1 -> 26.03.1 switched the train by slot PATH (pkg_repo_conf_path ->
pfSense-repo-0000.conf, the GUI's own persistence model). After the reboot
pfSense-repoc re-enumerated the slots — 0000 was suddenly the 26.07 RC train,
0001 the stable 26_03_1 — so config + symlink silently pinned the box to the
RC train and `pfSense-upgrade -c` offered "26.07.r.20260801.1756". The agent
now records the intended train BY NAME before an orbit-initiated update and
re-points the branch on the next firmware check when the active train no
longer matches.
"""

from __future__ import annotations

import json
from pathlib import Path

import orbit_agent as agent
import pytest


def _reset_state() -> None:
    agent._STATE.fw_verdict = {}
    agent._STATE.fw_check_ts = 0.0


def _pin_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    pin = tmp_path / "orbit-agent.train"
    monkeypatch.setattr(agent, "_TRAIN_PIN_FILE", str(pin))
    return pin


def _capture_popen(monkeypatch: pytest.MonkeyPatch) -> dict:
    captured: dict = {}

    def fake_popen(cmd: list[str], **kwargs: object) -> object:
        captured["cmd"] = cmd
        return object()

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    return captured


# ---------------------------------------------------------------- pin writers


def test_firmware_upgrade_pins_the_target_train(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin = _pin_file(monkeypatch, tmp_path)
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_root_free_mb", lambda: 99999)
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "25_07_1")
    monkeypatch.setattr(agent, "_pfsense_newer_branch", lambda active: ("26_03_1", "26.03.1"))
    monkeypatch.setattr(agent, "_pfsense_switch_train", lambda train: "")
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "25.07.1-RELEASE")
    monkeypatch.setattr(agent, "_zfs_boot_snapshot", lambda v: "")
    monkeypatch.setattr(agent, "_pfsense_wait_updater_idle", lambda timeout_s=180.0: True)
    _capture_popen(monkeypatch)
    result = agent.execute_command("firmware.upgrade", {})
    assert result["success"] is True
    assert json.loads(pin.read_text()) == {"train": "26_03_1", "attempts": 0}


def test_firmware_update_pins_the_current_train(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # An in-train update also reboots through repoc — the pin must record the
    # branch the box is supposed to STAY on.
    pin = _pin_file(monkeypatch, tmp_path)
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_root_free_mb", lambda: 99999)
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "26_03_1")
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "26.03.1-RELEASE")
    monkeypatch.setattr(agent, "_zfs_boot_snapshot", lambda v: "")
    monkeypatch.setattr(agent, "_pfsense_wait_updater_idle", lambda timeout_s=180.0: True)
    _capture_popen(monkeypatch)
    result = agent.execute_command("firmware.update", {})
    assert result["success"] is True
    assert json.loads(pin.read_text()) == {"train": "26_03_1", "attempts": 0}


def test_firmware_update_without_branch_writes_no_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin = _pin_file(monkeypatch, tmp_path)
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_root_free_mb", lambda: 99999)
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "")
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "26.03.1-RELEASE")
    monkeypatch.setattr(agent, "_zfs_boot_snapshot", lambda v: "")
    monkeypatch.setattr(agent, "_pfsense_wait_updater_idle", lambda timeout_s=180.0: True)
    _capture_popen(monkeypatch)
    result = agent.execute_command("firmware.update", {})
    assert result["success"] is True
    assert not pin.exists()


def test_opnsense_update_writes_no_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin = _pin_file(monkeypatch, tmp_path)
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    monkeypatch.setattr(agent, "_root_free_mb", lambda: 99999)
    monkeypatch.setattr(agent, "_read_opnsense_version", lambda: "26.1.11")
    monkeypatch.setattr(agent, "_zfs_boot_snapshot", lambda v: "")
    _capture_popen(monkeypatch)
    result = agent.execute_command("firmware.update", {})
    assert result["success"] is True
    assert not pin.exists()


# ------------------------------------------------------------------ the heal


def test_heal_repins_after_slot_reorder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin = _pin_file(monkeypatch, tmp_path)
    pin.write_text(json.dumps({"train": "26_03_1", "attempts": 0}))
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "26_07")
    monkeypatch.setattr(agent, "_list_pfsense_branches", lambda: ["26_07", "26_03_1"])
    switched: list[str] = []

    def fake_switch(train: str) -> str:
        switched.append(train)
        return ""

    monkeypatch.setattr(agent, "_pfsense_switch_train", fake_switch)
    monkeypatch.setattr(agent, "_pfsense_wait_updater_idle", lambda timeout_s=180.0: True)
    healed, note = agent._pfsense_heal_train_pin()
    assert healed is True
    assert switched == ["26_03_1"]
    assert "26_03_1" in note
    assert not pin.exists()


def test_heal_is_noop_without_pin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _pin_file(monkeypatch, tmp_path)

    def boom(train: str) -> str:
        raise AssertionError("must not switch without a pin")

    monkeypatch.setattr(agent, "_pfsense_switch_train", boom)
    assert agent._pfsense_heal_train_pin() == (False, "")


def test_heal_clears_pin_when_already_on_train(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pin = _pin_file(monkeypatch, tmp_path)
    pin.write_text(json.dumps({"train": "26_03_1", "attempts": 0}))
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "26_03_1")

    def boom(train: str) -> str:
        raise AssertionError("must not switch when the pin already matches")

    monkeypatch.setattr(agent, "_pfsense_switch_train", boom)
    assert agent._pfsense_heal_train_pin() == (False, "")
    assert not pin.exists()


def test_heal_clears_pin_when_train_vanished(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # After the NEXT series upgrade the vendor may drop the pinned train
    # entirely — there is nothing safe to re-pin to.
    pin = _pin_file(monkeypatch, tmp_path)
    pin.write_text(json.dumps({"train": "25_07_1", "attempts": 0}))
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "26_07")
    monkeypatch.setattr(agent, "_list_pfsense_branches", lambda: ["26_07", "26_03_1"])

    def boom(train: str) -> str:
        raise AssertionError("must not switch to a train the vendor dropped")

    monkeypatch.setattr(agent, "_pfsense_switch_train", boom)
    assert agent._pfsense_heal_train_pin() == (False, "")
    assert not pin.exists()


def test_heal_gives_up_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A box where the GUI switch code path keeps erroring must not fight a
    # (possibly deliberate) branch choice forever.
    pin = _pin_file(monkeypatch, tmp_path)
    pin.write_text(json.dumps({"train": "26_03_1", "attempts": 0}))
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: "26_07")
    monkeypatch.setattr(agent, "_list_pfsense_branches", lambda: ["26_07", "26_03_1"])
    monkeypatch.setattr(agent, "_pfsense_switch_train", lambda train: "php exploded")
    for _ in range(agent._TRAIN_PIN_MAX_ATTEMPTS):
        healed, note = agent._pfsense_heal_train_pin()
        assert healed is False
        assert "failed" in note
    assert json.loads(pin.read_text())["attempts"] == agent._TRAIN_PIN_MAX_ATTEMPTS
    # Attempts exhausted: pin is dropped, no further switch calls.
    monkeypatch.setattr(
        agent,
        "_pfsense_switch_train",
        lambda train: (_ for _ in ()).throw(AssertionError("attempts exhausted")),
    )
    assert agent._pfsense_heal_train_pin() == (False, "")
    assert not pin.exists()


# -------------------------------------------------- check-path integration


def test_collect_firmware_rechecks_after_heal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A healed branch invalidates the just-run `-c` (it checked the wrong,
    mis-pinned train) — the verdict must come from a fresh post-heal check."""
    _reset_state()
    pin = _pin_file(monkeypatch, tmp_path)
    pin.write_text(json.dumps({"train": "26_03_1", "attempts": 0}))
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "26.03.1-RELEASE")
    monkeypatch.setattr(agent, "_vendor_updater_running", lambda plat: False)
    branches = {"active": "26_07"}
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: branches["active"])
    monkeypatch.setattr(agent, "_list_pfsense_branches", lambda: ["26_07", "26_03_1"])
    monkeypatch.setattr(agent, "_pfsense_newer_train_verdict", lambda b, u, l, o: (u, l, "", o))
    monkeypatch.setattr(agent, "_pfsense_wait_updater_idle", lambda timeout_s=180.0: True)

    def fake_switch(train: str) -> str:
        branches["active"] = train
        return ""

    monkeypatch.setattr(agent, "_pfsense_switch_train", fake_switch)
    checks: list[str] = []

    def fake_run(cmd: list[str], *a: object, **k: object) -> str:
        if "-c" in cmd:
            checks.append(branches["active"])
            if branches["active"] == "26_07":
                return "26.07.r.20260801.1756 version of pfSense is available"
            return "Your system is up to date"
        return ""

    monkeypatch.setattr(agent, "_run", fake_run)
    fw = agent.collect_firmware()
    # One check on the mis-pinned train, one fresh check after the heal.
    assert checks == ["26_07", "26_03_1"]
    assert fw["branch"] == "26_03_1"
    assert fw["upgrade_available"] is False
    assert "re-pinned" in fw["update_check_output"]
    assert not pin.exists()
    _reset_state()


def test_manual_check_rechecks_after_heal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _reset_state()
    pin = _pin_file(monkeypatch, tmp_path)
    pin.write_text(json.dumps({"train": "26_03_1", "attempts": 0}))
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    monkeypatch.setattr(agent, "_read_pfsense_version", lambda: "26.03.1-RELEASE")
    branches = {"active": "26_07"}
    monkeypatch.setattr(agent, "_read_pfsense_branch", lambda: branches["active"])
    monkeypatch.setattr(agent, "_list_pfsense_branches", lambda: ["26_07", "26_03_1"])
    monkeypatch.setattr(agent, "_pfsense_newer_train_verdict", lambda b, u, l, o: (u, l, "", o))
    monkeypatch.setattr(agent, "_pfsense_wait_updater_idle", lambda timeout_s=180.0: True)

    def fake_switch(train: str) -> str:
        branches["active"] = train
        return ""

    monkeypatch.setattr(agent, "_pfsense_switch_train", fake_switch)
    checks: list[str] = []

    def fake_run(cmd: list[str], *a: object, **k: object) -> str:
        if "-c" in cmd:
            checks.append(branches["active"])
            return "Your system is up to date"
        return ""

    monkeypatch.setattr(agent, "_run", fake_run)
    result = agent.execute_command("firmware.check", {})
    assert result["success"] is True
    assert checks == ["26_07", "26_03_1"]
    assert result["branch"] == "26_03_1"
    assert "re-pinned" in result["output"]
    _reset_state()
