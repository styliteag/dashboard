"""Linux package-update checks via apt/dnf (§25) — security-only WARN semantics.

upgrade_available must be True only when *security* updates are pending;
routine updates ride along as counts. No package manager / failed refresh
must surface as check_failed, never as a false green.
"""

from __future__ import annotations

from types import SimpleNamespace

import orbit_agent as agent

APT_LIST = """Listing...
base-files/noble-updates 13ubuntu10.2 amd64 [upgradable from: 13ubuntu10]
openssl/noble-security 3.0.13-0ubuntu3.2 amd64 [upgradable from: 3.0.13-0ubuntu3.1]
vim/noble-updates 2:9.1.0-1ubuntu9 amd64 [upgradable from: 2:9.1.0-1ubuntu8]
"""

DNF_CHECK = """kernel.x86_64    5.14.0-500.el9    baseos
openssl.x86_64   3.2.2-6.el9       baseos
"""

DNF_SEC = "RHSA-2026:1234 Important/Sec. openssl-3.2.2-6.el9.x86_64\n"


def _fake_apt(monkeypatch, apt_out: str = APT_LIST, refresh_rc: int = 0) -> None:
    monkeypatch.setattr(
        agent.shutil, "which", lambda n: "/usr/bin/apt-get" if n == "apt-get" else None
    )
    monkeypatch.setattr(
        agent.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=refresh_rc, stdout="", stderr="mirror down"),
    )
    monkeypatch.setattr(
        agent, "_run", lambda cmd, timeout=5: apt_out if "apt list" in cmd[-1] else ""
    )


def test_apt_counts_security_drives_upgrade_available(monkeypatch) -> None:
    _fake_apt(monkeypatch)
    monkeypatch.setattr(agent.os.path, "exists", lambda p: p == "/var/run/reboot-required")
    upgrade_available, out, check_failed, extra = agent._apt_update_check()
    assert upgrade_available is True  # one -security row
    assert check_failed is False
    assert extra["updates_available"] == 3
    assert extra["security_updates"] == 1
    assert extra["needs_reboot"] is True
    assert {"name": "openssl", "current": "3.0.13-0ubuntu3.1", "new": "3.0.13-0ubuntu3.2"} in (
        extra["packages"]
    )
    assert "3 update(s) pending, 1 security" in out


def test_apt_routine_updates_stay_ok(monkeypatch) -> None:
    routine = "\n".join(ln for ln in APT_LIST.splitlines() if "-security" not in ln)
    _fake_apt(monkeypatch, apt_out=routine)
    monkeypatch.setattr(agent.os.path, "exists", lambda p: False)
    upgrade_available, _out, check_failed, extra = agent._apt_update_check()
    assert upgrade_available is False
    assert extra["updates_available"] == 2
    assert extra["security_updates"] == 0
    assert check_failed is False


def test_apt_refresh_failure_marks_check_failed(monkeypatch) -> None:
    _fake_apt(monkeypatch, refresh_rc=100)
    monkeypatch.setattr(agent.os.path, "exists", lambda p: False)
    _up, out, check_failed, _extra = agent._apt_update_check()
    assert check_failed is True
    assert "apt-get update failed" in out


def test_dnf_counts_and_security(monkeypatch) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda n: "/usr/bin/dnf" if n == "dnf" else None)
    monkeypatch.setattr(
        agent.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=100, stdout=DNF_CHECK, stderr=""),
    )
    monkeypatch.setattr(
        agent, "_run", lambda cmd, timeout=5: DNF_SEC if "updateinfo" in cmd[-1] else ""
    )
    upgrade_available, _out, check_failed, extra = agent._dnf_update_check()
    assert upgrade_available is True
    assert check_failed is False
    assert extra["updates_available"] == 2
    assert extra["security_updates"] == 1


def test_no_package_manager_is_check_failed_not_green(monkeypatch) -> None:
    monkeypatch.setattr(agent.shutil, "which", lambda n: None)
    upgrade_available, _latest, out, check_failed, extra = agent._linux_update_check()
    assert upgrade_available is False
    assert check_failed is True
    assert "no supported package manager" in out
    assert extra == {}


def test_collect_firmware_linux_branch(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_read_linux_version", lambda: "Ubuntu 26.04 LTS")
    monkeypatch.setattr(
        agent,
        "_linux_update_check",
        lambda: (True, "Ubuntu 26.04 LTS", "2 update(s) pending, 2 security", False,
                 {"updates_available": 2, "security_updates": 2, "needs_reboot": False,
                  "packages": []}),
    )
    agent._STATE.fw_verdict = {}
    agent._STATE.fw_check_ts = 0.0
    fw = agent.collect_firmware()
    assert fw["product_version"] == "Ubuntu 26.04 LTS"
    assert fw["upgrade_available"] is True
    assert fw["security_updates"] == 2
    assert fw["branch"] == ""
    # Verdict is cached for the throttle window.
    assert agent._STATE.fw_verdict["security_updates"] == 2
    agent._STATE.fw_verdict = {}
    agent._STATE.fw_check_ts = 0.0


def test_cmd_firmware_update_linux_apt_no_reboot(monkeypatch) -> None:
    calls: list = []
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(
        agent.shutil, "which", lambda n: "/usr/bin/apt-get" if n == "apt-get" else None
    )
    monkeypatch.setattr(
        agent.subprocess, "Popen", lambda cmd, **kw: calls.append((cmd, kw)) or None
    )
    result = agent._cmd_firmware_update({})
    assert result["success"] is True
    assert "no automatic reboot" in result["output"]
    cmd, kw = calls[0]
    assert cmd[0] == "apt-get" and "upgrade" in cmd
    assert kw["env"]["DEBIAN_FRONTEND"] == "noninteractive"


def test_cmd_firmware_update_linux_without_pkg_manager_fails(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent.shutil, "which", lambda n: None)
    result = agent._cmd_firmware_update({})
    assert result["success"] is False


def test_linux_update_check_serializes_concurrent_callers(monkeypatch) -> None:
    """Push loop + manual firmware.check run on different threads; concurrent
    apt-get invocations fought over the dpkg lists lock (live on ubn1)."""
    import threading
    import time as _time

    active = []
    overlaps = []

    def slow_check():
        active.append(1)
        if len(active) > 1:
            overlaps.append(1)
        _time.sleep(0.05)
        active.pop()
        return False, "0 update(s) pending, 0 security", False, {}

    monkeypatch.setattr(agent.shutil, "which", lambda n: "/usr/bin/apt-get" if n == "apt-get" else None)
    monkeypatch.setattr(agent, "_apt_update_check", slow_check)
    threads = [threading.Thread(target=agent._linux_update_check) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert overlaps == []


def test_collect_firmware_failed_check_retries_early(monkeypatch) -> None:
    """A transient failure (apt lock held) must not pin WARN for the 12h window."""
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_read_linux_version", lambda: "Ubuntu 26.04 LTS")
    monkeypatch.setattr(
        agent, "_linux_update_check", lambda: (False, "Ubuntu 26.04 LTS", "locked", True, {})
    )
    agent._STATE.fw_verdict = {}
    agent._STATE.fw_check_ts = 0.0
    fw = agent.collect_firmware()
    assert fw["check_failed"] is True
    import time as _time

    remaining = agent._FW_CHECK_INTERVAL_S - (_time.monotonic() - agent._STATE.fw_check_ts)
    assert remaining <= agent._FW_FAILED_RETRY_S + 5
    agent._STATE.fw_verdict = {}
    agent._STATE.fw_check_ts = 0.0
