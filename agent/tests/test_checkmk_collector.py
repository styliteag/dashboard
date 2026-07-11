"""collect_checkmk — transport-only bridge to the vendored Checkmk agent (§25/DR-10).

The collector must be inert everywhere except a Linux host with a usable
script, and must ship raw output verbatim (gzip+base64) — parsing is the
backend's job. Every failure mode maps to {} so a broken script can never
blank or abort the push cycle.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import stat

import orbit_agent as agent


def _script(tmp_path, body: str) -> str:
    p = tmp_path / "check_mk_agent.linux"
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return str(p)


def test_non_linux_platform_returns_empty(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    assert agent.collect_checkmk() == {}


def test_linux_without_script_returns_empty(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_CHECKMK_CANDIDATES", (str(tmp_path / "missing"),))
    assert agent.collect_checkmk() == {}


def test_linux_script_output_ships_gzipped_and_hashed(monkeypatch, tmp_path) -> None:
    path = _script(tmp_path, 'printf "<<<check_mk>>>\\nVersion: 2.5.0p8\\n"')
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_CHECKMK_CANDIDATES", (path,))
    out = agent.collect_checkmk()
    raw = gzip.decompress(base64.b64decode(out["output_gz_b64"]))
    assert raw == b"<<<check_mk>>>\nVersion: 2.5.0p8\n"
    assert out["size"] == len(raw)
    assert out["sha256"] == hashlib.sha256(raw).hexdigest()


def test_oversize_output_dropped_not_truncated(monkeypatch, tmp_path) -> None:
    path = _script(tmp_path, 'printf "<<<check_mk>>>\\nVersion: x\\n"')
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_CHECKMK_CANDIDATES", (path,))
    monkeypatch.setattr(agent, "_CHECKMK_MAX", 4)
    assert agent.collect_checkmk() == {}


def test_empty_output_returns_empty(monkeypatch, tmp_path) -> None:
    path = _script(tmp_path, "true")
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_CHECKMK_CANDIDATES", (path,))
    assert agent.collect_checkmk() == {}


def test_hanging_script_times_out_to_empty(monkeypatch, tmp_path) -> None:
    path = _script(tmp_path, "sleep 5")
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_CHECKMK_CANDIDATES", (path,))
    monkeypatch.setattr(agent, "_CHECKMK_TIMEOUT", 0.2)
    assert agent.collect_checkmk() == {}


def test_registered_as_snapshot_section() -> None:
    assert ("checkmk_raw", "collect_checkmk") in agent._SNAPSHOT_SECTIONS


# --- checkmk.update: signed deploy of the vendored script (§25/DR-10) ---------


def _deploy_params(code: bytes) -> dict:
    import hashlib

    return {
        "code": base64.b64encode(code).decode(),
        "sha256": hashlib.sha256(code).hexdigest(),
        "signature": "",
    }


def test_checkmk_update_rejects_non_linux(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "opnsense")
    result = agent._cmd_checkmk_update(_deploy_params(b"#!/bin/bash\n"))
    assert result["success"] is False and "linux-only" in result["output"]


def test_checkmk_update_rejects_sha_mismatch(monkeypatch) -> None:
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    params = _deploy_params(b"#!/bin/bash\n")
    params["sha256"] = "0" * 64
    result = agent._cmd_checkmk_update(params)
    assert result["success"] is False and "sha256 mismatch" in result["output"]


def test_checkmk_update_rejects_bad_signature(monkeypatch) -> None:
    """With a baked pubkey, unsigned root code must never be written."""
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_signature_ok", lambda code, sig: False)
    result = agent._cmd_checkmk_update(_deploy_params(b"#!/bin/bash\n"))
    assert result["success"] is False and "signature" in result["output"]


def test_checkmk_update_writes_atomically_with_exec_bit(monkeypatch, tmp_path) -> None:
    import stat as _stat

    target = tmp_path / "deploy" / "check_mk_agent.linux"
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_signature_ok", lambda code, sig: True)
    monkeypatch.setattr(agent, "_CHECKMK_DEPLOY_PATH", str(target))
    code = b"#!/bin/bash\necho '<<<check_mk>>>'\n"
    result = agent._cmd_checkmk_update(_deploy_params(code))
    assert result["success"] is True
    assert target.read_bytes() == code
    assert target.stat().st_mode & _stat.S_IXUSR
    # No temp litter left behind.
    assert [p.name for p in target.parent.iterdir()] == [target.name]


def test_checkmk_script_sha_reports_deployed_copy(monkeypatch, tmp_path) -> None:
    import hashlib

    path = _script(tmp_path, "true")
    monkeypatch.setattr(agent, "detect_platform", lambda: "linux")
    monkeypatch.setattr(agent, "_CHECKMK_CANDIDATES", (path,))
    expected = hashlib.sha256(open(path, "rb").read()).hexdigest()
    assert agent._checkmk_script_sha() == expected
    monkeypatch.setattr(agent, "_CHECKMK_CANDIDATES", (str(tmp_path / "missing"),))
    assert agent._checkmk_script_sha() == ""
    monkeypatch.setattr(agent, "detect_platform", lambda: "pfsense")
    assert agent._checkmk_script_sha() == ""
