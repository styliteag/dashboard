"""Pure extraction logic for critical log events (see app.logs.events).

Covers both syslog shapes seen in prod snapshots: RFC5424 with <PRI> (OPNsense,
most pfSense logs) and PRI-less BSD lines (dpinger, older pfSense), plus the
curated noise filter and the normalization that powers aggregation.
"""

from __future__ import annotations

from app.logs.events import MAX_SEVERITY, extract_events, normalize

_RFC = '<{pri}>1 2026-07-04T11:29:46+02:00 fw1 {app} 98100 - [meta x="1"] {msg}'
_BSD = "Jul  4 10:39:55 pfSense {prog}[428]: {msg}"


def _rfc(pri: int, app: str, msg: str) -> str:
    return _RFC.format(pri=pri, app=app, msg=msg)


def _bsd(prog: str, msg: str) -> str:
    return _BSD.format(prog=prog, msg=msg)


def test_pri_severity_filter() -> None:
    content = "\n".join(
        [
            _rfc(11, "openvpn", "TLS Error: TLS handshake failed"),  # 11 % 8 = 3 err
            _rfc(29, "dhcp6c", "Sending Renew on vtnet0"),  # 29 % 8 = 5 notice → dropped
            _rfc(14, "sshd", "something went wrong"),  # 14 % 8 = 6 info → dropped
        ]
    )
    events = extract_events("openvpn", content)
    assert len(events) == 1
    assert events[0].severity == 3
    assert events[0].program == "openvpn"
    assert "TLS handshake failed" in events[0].pattern


def test_warning_kept_but_nothing_above_max() -> None:
    content = _rfc(12, "dhcpd", "peer holds all free leases")  # 12 % 8 = 4 warning
    events = extract_events("dhcp", content)
    assert len(events) == 1
    assert events[0].severity == 4
    assert MAX_SEVERITY == 4


def test_aggregation_normalizes_ips_and_numbers() -> None:
    content = "\n".join(
        [
            _rfc(11, "openvpn", "203.0.113.7:1194 Connection reset, restarting [0]"),
            _rfc(11, "openvpn", "198.51.100.9:1194 Connection reset, restarting [3]"),
        ]
    )
    events = extract_events("openvpn", content)
    assert len(events) == 1
    assert events[0].count == 2
    assert "203.0.113.7" not in events[0].pattern
    # Sample keeps the raw (last) line for context.
    assert "198.51.100.9" in events[0].sample


def test_bsd_curated_patterns_get_severity() -> None:
    content = "\n".join(
        [
            _bsd("kernel", "panic: out of swap space"),
            _bsd("php-fpm", "/rc.newwanipv6: rc.newwanipv6: Info: starting on vtnet1."),
        ]
    )
    events = extract_events("system", content)
    assert len(events) == 1
    assert events[0].severity == 2
    assert events[0].program == "kernel"


def test_noise_is_dropped_in_both_shapes() -> None:
    content = "\n".join(
        [
            _bsd("dpinger", "PPPOE_WAN_PPPOE 10.0.0.1: sendto error: 65"),
            _bsd("filterdns", "failed to resolve host x.example.com will retry later again."),
            _rfc(11, "filterdns", "failed to resolve host y.example.com will retry later again."),
        ]
    )
    assert extract_events("gateways", content) == []


def test_normalize_masks_variable_parts() -> None:
    n = normalize('user "bob" from 10.1.2.3 port 55123 failed 3 times fe80::1%igc0')
    assert "10.1.2.3" not in n
    assert "55123" not in n
    assert "bob" not in n  # quoted strings masked


def test_last_timestamp_wins() -> None:
    content = "\n".join(
        [
            "<11>1 2026-07-04T09:00:00+02:00 fw1 openvpn 1 - - TLS Error: TLS handshake failed",
            "<11>1 2026-07-04T11:30:00+02:00 fw1 openvpn 1 - - TLS Error: TLS handshake failed",
        ]
    )
    events = extract_events("openvpn", content)
    assert len(events) == 1
    assert events[0].last_ts == "2026-07-04T11:30:00+02:00"
