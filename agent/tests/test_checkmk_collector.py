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
