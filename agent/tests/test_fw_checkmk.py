"""Checkmk script on the firewall line (OPNsense, pfSense; shared bridge
agent/src/shared/checkmk.py).

Off until the dashboard asks for it (welcome / config_update `checkmk`), so a
firewall without that flag behaves as before and sends no checkmk_raw. When on:
our signed FreeBSD copy only, started as `/bin/sh <path>`, at most once per
60 s, never twice at once. A run that exits non-zero, times out or yields
fewer than 3 sections sends no output, only a short status; the output is
marked transport only (the dashboard keeps the firewall's own values).
"""

from __future__ import annotations

import base64
import gzip
import hashlib

import orbit_agent as agent
import pytest

THREE = '<<<check_mk>>>\\nVersion: x\\n<<<df>>>\\na\\n<<<uptime>>>\\n1\\n'


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    agent._STATE.checkmk_ts = 0.0
    agent._STATE.checkmk_status = None
    agent._STATE.checkmk_enabled = True
    yield
    agent._STATE.checkmk_ts = 0.0
    agent._STATE.checkmk_status = None
    agent._STATE.checkmk_enabled = False


def _script(monkeypatch, tmp_path, body: str):
    # no exec bit needed beyond the check; run through /bin/sh anyway
    p = tmp_path / "check_mk_agent.freebsd"
    p.write_text(body + "\n")
    p.chmod(0o755)
    monkeypatch.setattr(agent, "_CHECKMK_CANDIDATES", (str(p),))
    return str(p)


def _run():
    payload = agent.collect_checkmk()
    return payload, agent.collect_checkmk_status()


def test_flag_off_no_run_no_section(monkeypatch, tmp_path):
    agent._STATE.checkmk_enabled = False
    monkeypatch.setattr(agent, "_checkmk_exec", lambda argv: pytest.fail("ran"))
    _script(monkeypatch, tmp_path, "printf '%s' '" + THREE + "'")

    assert _run() == ({}, {})


def test_a_good_run_ships_transport_only_output_through_bin_sh(monkeypatch, tmp_path):
    path = _script(monkeypatch, tmp_path, "printf '" + THREE + "'")
    seen = []
    real = agent._checkmk_exec
    monkeypatch.setattr(agent, "_checkmk_exec", lambda argv: seen.append(argv) or real(argv))

    payload, status = _run()

    assert seen == [["/bin/sh", path]]
    raw = gzip.decompress(base64.b64decode(payload["output_gz_b64"]))
    assert raw.startswith(b"<<<check_mk>>>")
    assert payload["transport_only"] is True and payload["interval"] == 60
    assert payload["sha256"] == hashlib.sha256(raw).hexdigest()
    assert status == {"ok": True, "reason": "", "sections": 3, "interval": 60}


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ("printf '" + THREE + "'; exit 2", "exit code 2"),
        ("printf '<<<check_mk>>>\\nVersion: x\\n'", "only 1 section"),
        ("sleep 5", "timed out after 0 s"),
    ],
)
def test_a_failed_run_sends_no_output_only_a_reason(monkeypatch, tmp_path, body, reason):
    monkeypatch.setattr(agent, "_CHECKMK_TIMEOUT", 0.3)
    _script(monkeypatch, tmp_path, body)

    payload, status = _run()

    assert payload == {}
    assert status["ok"] is False and status["reason"] == reason


def test_at_most_once_per_interval_and_never_twice_at_once(monkeypatch, tmp_path):
    _script(monkeypatch, tmp_path, "printf '" + THREE + "'")
    clock = [-1000.0]
    monkeypatch.setattr(agent.time, "monotonic", lambda: clock[0])

    assert agent._CHECKMK_LOCK.acquire(blocking=False)
    try:
        assert agent.collect_checkmk() == {}  # a run is going
    finally:
        agent._CHECKMK_LOCK.release()
    assert agent.collect_checkmk()["output_gz_b64"]
    clock[0] += 30
    assert agent.collect_checkmk() == {}
    clock[0] += 30
    assert agent.collect_checkmk()["output_gz_b64"]


def test_update_verifies_the_signature_before_writing(monkeypatch, tmp_path):
    target = tmp_path / "check_mk_agent.freebsd"
    monkeypatch.setattr(agent, "_CHECKMK_DEPLOY_PATH", str(target))
    monkeypatch.setattr(agent, "_skip_sig_check", lambda: False)
    monkeypatch.setattr(agent, "_signature_ok", lambda code, sig: False)
    code = b"#!/usr/local/bin/bash\necho '<<<check_mk>>>'\n"
    params = {
        "code": base64.b64encode(code).decode(),
        "sha256": hashlib.sha256(code).hexdigest(),
        "signature": "AAAA",
    }

    result = agent.execute_command("checkmk.update", params)

    assert result["success"] is False and "signature" in result["output"]
    assert not target.exists()

    monkeypatch.setattr(agent, "_signature_ok", lambda code, sig: True)
    assert agent.execute_command("checkmk.update", params)["success"] is True
    assert target.read_bytes() == code


def test_the_dashboard_flag_switches_it(monkeypatch):
    agent._STATE.checkmk_enabled = False
    agent._apply_checkmk_enabled(True)
    assert agent._STATE.checkmk_enabled is True
    agent._apply_checkmk_enabled("yes")  # junk is ignored
    assert agent._STATE.checkmk_enabled is True
    agent._apply_checkmk_enabled(False)
    assert agent._STATE.checkmk_enabled is False
