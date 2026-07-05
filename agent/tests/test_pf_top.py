"""Tests for the pf state-table insight collector (collect_pf_top).

Fixture lines are verbatim `pfctl -vss` output captured on the lab boxes
(OPNsense 2.6.11 / pfSense CE 2.8.1) — keep them byte-faithful, the parser is
calibrated against exactly this format.
"""

from __future__ import annotations

import orbit_agent as agent

# Real capture: floating (all) + if-bound states, v4/v6, NAT-less. Includes the
# ALTQ warning noise pfctl emits on stderr-merged runs and a TCP wscale line.
_SAMPLE = """\
No ALTQ support in kernel
ALTQ related functions disabled
all udp 224.0.0.251:5353 <- 10.20.1.63:5353       NO_TRAFFIC:SINGLE
   age 15:55:48, expires in 00:00:27, 7299:0 pkts, 862474:0 bytes, rule 97
vtnet0 esp 10.21.7.102 -> 10.21.7.100       MULTIPLE:MULTIPLE
   age 12:45:07, expires in 00:00:44, 8484:8484 pkts, 1187760:1187760 bytes, rule 93, allow-opts
vtnet1 tcp 10.20.1.200:26593 -> 10.20.0.24:8000       FIN_WAIT_2:FIN_WAIT_2
   [960641462 + 141248] wscale 7  [1644044985 + 65792] wscale 6
   age 10:35:08, expires in 00:00:19, 24894:13640 pkts, 21346306:689950 bytes, rule 93, allow-opts
vtnet1 udp ff02::1:2[547] <- fe80::be24:20ff:fead:1994[546]       NO_TRAFFIC:SINGLE
   age 07:33:32, expires in 00:00:16, 3014:0 pkts, 441515:0 bytes, rule 87
vtnet0 icmp 10.21.7.102:21310 -> 10.21.4.1:8       0:0
   age 06:54:06, expires in 00:00:10, 46991:46991 pkts, 1362739:1362739 bytes, rule 95, allow-opts
""".splitlines()


def test_parse_header_outbound_v4() -> None:
    h = agent._pf_parse_header("vtnet1 tcp 10.20.1.200:26593 -> 10.20.0.24:8000       FIN_WAIT_2:FIN_WAIT_2")
    assert h == {
        "iface": "vtnet1",
        "proto": "tcp",
        "src": "10.20.1.200",
        "sport": "26593",
        "dst": "10.20.0.24",
        "dport": "8000",
        "state": "FIN_WAIT_2:FIN_WAIT_2",
    }


def test_parse_header_inbound_swaps_src_dst() -> None:
    # pf prints inbound states destination-first: "dst <- src"
    h = agent._pf_parse_header("all udp 224.0.0.251:5353 <- 10.20.1.63:5353       NO_TRAFFIC:SINGLE")
    assert h is not None
    assert h["src"] == "10.20.1.63"
    assert h["dst"] == "224.0.0.251"


def test_parse_header_v6_bracket_ports_and_bare_esp() -> None:
    h6 = agent._pf_parse_header(
        "vtnet1 udp ff02::1:2[547] <- fe80::be24:20ff:fead:1994[546]       NO_TRAFFIC:SINGLE"
    )
    assert h6 is not None
    assert (h6["src"], h6["sport"]) == ("fe80::be24:20ff:fead:1994", "546")
    assert (h6["dst"], h6["dport"]) == ("ff02::1:2", "547")
    hesp = agent._pf_parse_header("all esp 10.21.7.100 <- 10.21.7.101       MULTIPLE:MULTIPLE")
    assert hesp is not None
    assert (hesp["src"], hesp["sport"]) == ("10.21.7.101", "")


def test_parse_header_nat_prefers_pre_nat_address() -> None:
    h = agent._pf_parse_header(
        "em0 tcp 203.0.113.9:61000 (10.0.0.5:52134) -> 8.8.8.8:53       ESTABLISHED:ESTABLISHED"
    )
    assert h is not None
    assert (h["src"], h["sport"]) == ("10.0.0.5", "52134")
    assert h["dst"] == "8.8.8.8"


def test_parse_header_rejects_noise() -> None:
    assert agent._pf_parse_header("No ALTQ support in kernel") is None
    assert agent._pf_parse_header("ALTQ related functions disabled") is None


def test_age_seconds() -> None:
    assert agent._pf_age_seconds("63:54:47") == 63 * 3600 + 54 * 60 + 47
    assert agent._pf_age_seconds("00:19") == 19
    assert agent._pf_age_seconds("junk") == 0


def test_aggregate_counts_states_bytes_and_ranks() -> None:
    s = agent._aggregate_pf_states(_SAMPLE)
    assert s["total_states"] == 5
    # interfaces: vtnet0 2, vtnet1 2, all 1
    by_if = {e["name"]: e for e in s["interfaces"]}
    assert by_if["vtnet0"]["states"] == 2
    assert by_if["vtnet1"]["states"] == 2
    assert by_if["all"]["states"] == 1
    # top source by bytes = the TCP flow (21346306+689950)
    assert s["top_sources"][0] == {
        "ip": "10.20.1.200",
        "states": 1,
        "bytes": 21346306 + 689950,
    }
    # wscale middle line must not eat the TCP flow's stats line
    top_flow = s["top_flows"][0]
    assert top_flow["src"] == "10.20.1.200"
    assert top_flow["bytes"] == 21346306 + 689950
    assert top_flow["pkts"] == 24894 + 13640
    assert top_flow["age_s"] == 10 * 3600 + 35 * 60 + 8
    # protocols carry both states and bytes
    protos = {e["proto"]: e for e in s["protocols"]}
    assert protos["udp"]["states"] == 2
    assert protos["esp"]["bytes"] == 1187760 * 2
    # flows ranked descending
    flow_bytes = [f["bytes"] for f in s["top_flows"]]
    assert flow_bytes == sorted(flow_bytes, reverse=True)


def test_aggregate_caps_top_lists() -> None:
    lines = []
    for i in range(agent._PFTOP_TOP_N + 5):
        lines.append(f"em0 tcp 10.0.0.{i}:1000 -> 192.0.2.{i}:443       ESTABLISHED:ESTABLISHED")
        lines.append(f"   age 00:01:00, expires in 00:01:00, 10:10 pkts, {100 + i}:0 bytes, rule 1")
    s = agent._aggregate_pf_states(lines)
    assert s["total_states"] == agent._PFTOP_TOP_N + 5
    assert len(s["top_sources"]) == agent._PFTOP_TOP_N
    assert len(s["top_flows"]) == agent._PFTOP_TOP_N
    # the smallest flows fell out of the heap
    assert min(f["bytes"] for f in s["top_flows"]) == 100 + 5


def test_collect_pf_top_caches_between_intervals(monkeypatch) -> None:
    calls = [0]

    def fake_lines():
        calls[0] += 1
        yield "em0 tcp 10.0.0.1:1 -> 10.0.0.2:2       ESTABLISHED:ESTABLISHED"
        yield "   age 00:01:00, expires in 00:01:00, 1:1 pkts, 5:5 bytes, rule 1"

    monkeypatch.setattr(agent, "_pf_state_lines", fake_lines)
    monkeypatch.setattr(agent, "_pftop_cache", [0.0, {}])
    first = agent.collect_pf_top()
    assert first["total_states"] == 1
    assert first["ts"]
    second = agent.collect_pf_top()
    assert second is first  # cached replay, no second pfctl walk
    assert calls[0] == 1


def test_collect_pf_top_recomputes_after_interval(monkeypatch) -> None:
    def fake_lines():
        yield "em0 udp 10.0.0.1:1 -> 10.0.0.2:2       NO_TRAFFIC:SINGLE"
        yield "   age 00:01:00, expires in 00:01:00, 1:0 pkts, 7:0 bytes, rule 1"

    monkeypatch.setattr(agent, "_pf_state_lines", fake_lines)
    stale = agent.time.monotonic() - agent._PFTOP_INTERVAL - 1
    monkeypatch.setattr(agent, "_pftop_cache", [stale, {"total_states": 99}])
    result = agent.collect_pf_top()
    assert result["total_states"] == 1
