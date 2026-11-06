"""Option injection into root-run tools (security hotfix).

The capture filter, the capture interface and the ping source/destination
come from the dashboard and end up in the argv of tcpdump / ping, run as
root on the box. Before the fix:

- the BPF filter was split on whitespace into argv tokens, so a "filter" of
  ``-w /path -C 1 -z cmd`` set tcpdump OPTIONS (write a file, post-rotate
  command) — on Linux always (glibc getopt permutes argv, the parentheses
  around the filter did not help), on FreeBSD whenever no agent-exclusion
  filter was prepended;
- a ping destination/source such as ``-f`` became a ping option (flood).

Now: the filter is ONE argument after ``--``; interface, ping source and
destination must be an IP literal / plain name without a leading ``-``, and
``--`` ends ping's options before the destination.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import orbit_agent as fw
import orbit_agent_linux as lx
import pytest

LINES = [fw, lx]
_OK = SimpleNamespace(
    stdout="3 packets transmitted, 3 packets received, 0.0% packet loss\n"
    "round-trip min/avg/max/stddev = 0.1/0.5/0.9/0.0 ms",
    stderr="",
    returncode=0,
)


@pytest.mark.parametrize("agent", LINES)
@pytest.mark.parametrize(
    "value,ok",
    [
        ("10.1.1.5", True),
        ("2001:db8::1", True),
        ("::1", True),
        ("fw.example.com", True),
        ("host-1_a", True),
        ("-f", False),
        ("-oProxyCommand=x", False),
        ("10.0.0.1 -f", False),
        ("a;b", False),
        ("", False),
        (None, False),
    ],
)
def test_safe_host_arg(agent, value, ok) -> None:
    assert (agent._safe_host_arg(value) != "") is ok


@pytest.mark.parametrize("agent", LINES)
@pytest.mark.parametrize("source,dest", [("10.1.1.5", "-f"), ("-f", "10.2.2.1")])
def test_ping_refuses_option_like_values_without_running(monkeypatch, agent, source, dest):
    ran: list = []
    monkeypatch.setattr(agent.subprocess, "run", lambda cmd, **k: ran.append(cmd) or _OK)
    assert agent._ping_once(source, dest, 3)["ping_state"] == "error"
    assert ran == []


@pytest.mark.parametrize("agent", LINES)
def test_ping_ends_options_before_the_destination(monkeypatch, agent) -> None:
    seen: list = []
    monkeypatch.setattr(agent.subprocess, "run", lambda cmd, **k: seen.append(cmd) or _OK)
    agent._ping_once("10.1.1.5", "10.2.2.1", 3)
    assert seen[0][-2:] == ["--", "10.2.2.1"]


@pytest.mark.parametrize("agent", LINES)
def test_packet_capture_passes_the_filter_as_one_argument(monkeypatch, agent) -> None:
    seen: list = []

    def fake_popen(cmd, **k):
        seen.append(cmd)
        raise FileNotFoundError

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(agent, "_agent_ws_exclude_bpf", lambda: "")
    evil = "-w /tmp/x -C 1 -z /bin/sh"
    agent._cmd_packet_capture({"interface": "em0", "filter": evil, "max_seconds": 1})
    assert seen[0][-2:] == ["--", evil]
    assert "-z" not in seen[0]


@pytest.mark.parametrize("agent", LINES)
def test_packet_capture_wraps_with_the_agent_exclusion(monkeypatch, agent) -> None:
    seen: list = []

    def fake_popen(cmd, **k):
        seen.append(cmd)
        raise FileNotFoundError

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(agent, "_agent_ws_exclude_bpf", lambda: "not host 9.9.9.9")
    agent._cmd_packet_capture({"interface": "em0", "filter": "port 53", "max_seconds": 1})
    assert seen[0][-2:] == ["--", "(port 53) and not host 9.9.9.9"]


@pytest.mark.parametrize("agent", LINES)
def test_packet_capture_refuses_an_option_like_interface(monkeypatch, agent) -> None:
    ran: list = []
    monkeypatch.setattr(agent.subprocess, "Popen", lambda cmd, **k: ran.append(cmd))
    res = agent._cmd_packet_capture({"interface": "-zsh", "filter": "", "max_seconds": 1})
    assert res["success"] is False
    assert ran == []


def _manager(agent):
    # firewall line: (ws, gui_host, gui_port); linux line has no GUI tunnel: (ws)
    try:
        return agent._TunnelManager(_FakeWs(), "127.0.0.1", 443)
    except TypeError:
        return agent._TunnelManager(_FakeWs())


class _FakeWs:
    def __init__(self) -> None:
        self.sent: list = []

    async def send(self, data) -> None:
        self.sent.append(data)


@pytest.mark.parametrize("agent", LINES)
def test_live_capture_passes_the_filter_as_one_argument(monkeypatch, agent) -> None:
    seen: list = []

    async def fake_exec(*cmd, **k):
        seen.append(list(cmd))
        raise OSError("stop here")

    monkeypatch.setattr(agent.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(agent, "_agent_ws_exclude_bpf", lambda: "")
    mgr = _manager(agent)
    evil = "-w /tmp/x -C 1 -z /bin/sh"
    asyncio.run(mgr._open_capture("s1", "em0", evil))
    assert seen[0][-2:] == ["--", evil]


@pytest.mark.parametrize("agent", LINES)
def test_live_capture_refuses_an_option_like_interface(monkeypatch, agent) -> None:
    seen: list = []

    async def fake_exec(*cmd, **k):
        seen.append(cmd)
        raise OSError

    monkeypatch.setattr(agent.asyncio, "create_subprocess_exec", fake_exec)
    mgr = _manager(agent)
    asyncio.run(mgr._open_capture("s1", "-zsh", ""))
    assert seen == []
