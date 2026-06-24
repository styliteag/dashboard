"""Tests for the Checkmk special-agent output transform (pure)."""

from __future__ import annotations

import agent_styliteorbit as cma

_EXPORT = {
    "version": 1,
    "instances": [
        {
            "instance_id": 3,
            "name": "opnsense 199",  # space → host gets sanitized
            "host": "opnsense 199",
            "device_type": "opnsense",
            "checks": [
                {
                    "key": "memory",
                    "state": 0,
                    "summary": "Memory 19% used (ok)",
                    "metrics": [
                        {"name": "mem_used_pct", "value": 19.4, "warn": 80.0, "crit": 90.0}
                    ],
                },
                {
                    "key": "gateway:WAN",
                    "state": 2,
                    "summary": "Gateway WAN down",
                    "metrics": [],
                },
            ],
        }
    ],
}


def test_piggyback_and_local_markers() -> None:
    out = cma.render_checkmk(_EXPORT)
    lines = out.splitlines()
    assert lines[0] == "<<<<opnsense_199>>>>"  # space → underscore
    assert lines[1] == "<<<local>>>"
    assert lines[-1] == "<<<<>>>>"


def test_local_line_format_with_perfdata() -> None:
    out = cma.render_checkmk(_EXPORT)
    # "<state> <item> <perfdata> <text>"
    mem = next(line for line in out.splitlines() if line.startswith("0 memory"))
    assert mem == "0 memory mem_used_pct=19.40;80;90 Memory 19% used (ok)"


def test_local_line_no_perfdata_uses_dash() -> None:
    out = cma.render_checkmk(_EXPORT)
    gw = next(line for line in out.splitlines() if line.startswith("2 gateway:WAN"))
    assert gw == "2 gateway:WAN - Gateway WAN down"


def _one_host(check: dict) -> dict:
    return {"instances": [{"name": "h", "checks": [check]}]}


def test_invalid_state_becomes_unknown() -> None:
    out = cma.render_checkmk(_one_host({"key": "x", "state": 9, "summary": "s"}))
    line = next(ln for ln in out.splitlines() if ln.startswith("3 "))
    assert line == "3 x - s"


def test_summary_pipe_is_escaped() -> None:
    out = cma.render_checkmk(_one_host({"key": "x", "state": 1, "summary": "a | b"}))
    line = next(ln for ln in out.splitlines() if ln.startswith("1 x"))
    assert "|" not in line.split(" ", 3)[3]  # text part has no pipe
