"""Tests for pfSense reboot self-healing (afterbootupshellcmd boot hook)."""

from __future__ import annotations

import orbit_agent as agent


def test_persist_skips_non_pfsense(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    calls = []
    monkeypatch.setattr(agent, "_run", lambda *a, **k: calls.append(a) or "")
    agent._ensure_pfsense_boot_persistence()
    assert calls == []  # no PHP invoked off pfSense


def test_persist_pfsense_writes_boot_hook(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    captured = {}

    def fake_run(cmd, timeout=5):
        # cmd == ["/usr/local/bin/php", <tmp php file>]; read it before removal.
        with open(cmd[1]) as fh:
            captured["php"] = fh.read()
        captured["bin"] = cmd[0]
        return "set"

    monkeypatch.setattr(agent, "_run", fake_run)
    agent._ensure_pfsense_boot_persistence()
    assert captured["bin"] == "/usr/local/bin/php"
    assert "afterbootupshellcmd" in captured["php"]
    assert "/usr/local/etc/rc.d/orbit_agent onestart" in captured["php"]
    assert "write_config" in captured["php"]
    # idempotent guard present
    assert "orbit_agent" in captured["php"] and "strpos" in captured["php"]


def test_persist_tolerates_php_failure(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")

    def boom(*a, **k):
        raise OSError("php missing")

    monkeypatch.setattr(agent, "_run", boom)
    # Must not raise — startup persistence is best-effort.
    agent._ensure_pfsense_boot_persistence()
