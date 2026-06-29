"""Tests for the out-of-band probe engine (pure parts + the run_probe combiner)."""

from __future__ import annotations

import struct

from app.probe import icmp
from app.probe.http import http_ok
from app.probe.runner import ProbeResult, http_target, run_probe, target_host

# --- ICMP packet helpers ----------------------------------------------------


def test_build_echo_request_is_self_consistent() -> None:
    pkt = icmp.build_echo_request(ident=1234, seq=1)
    # A correctly-checksummed ICMP packet has internet-checksum 0 over the whole.
    assert icmp.checksum(pkt) == 0
    typ, code = struct.unpack("!BB", pkt[:2])
    assert typ == 8 and code == 0  # echo request


def test_build_echo_request_masks_ident_and_seq() -> None:
    # Values are truncated to 16 bits, never overflow the header fields.
    pkt = icmp.build_echo_request(ident=0x1FFFF, seq=0x1_0001)
    _, _, _, ident, seq = struct.unpack("!BBHHH", pkt[:8])
    assert ident == 0xFFFF and seq == 1


def test_icmp_type_raw_vs_dgram() -> None:
    reply = struct.pack("!BBHHH", 0, 0, 0, 1, 1)  # echo reply, no IP header
    assert icmp.icmp_type(reply, raw=False) == 0
    assert icmp.icmp_type(b"\x45" + b"\x00" * 19 + reply, raw=True) == 0
    assert icmp.icmp_type(b"", raw=False) is None


# --- target extraction ------------------------------------------------------


def test_target_host_variants() -> None:
    assert target_host("https://10.20.1.198:4444") == "10.20.1.198"
    assert target_host("http://opn1.example/health") == "opn1.example"
    assert target_host("10.20.1.198") == "10.20.1.198"
    assert target_host("10.20.1.198:4444") == "10.20.1.198"
    assert target_host("") is None
    assert target_host(None) is None


def test_http_target_only_for_urls() -> None:
    assert http_target("https://10.20.1.198:4444") == "https://10.20.1.198:4444"
    assert http_target("10.20.1.198") is None  # bare host → ICMP only, no HTTP
    assert http_target("ftp://x") is None  # non-http scheme
    assert http_target(None) is None


# --- HTTP success classification --------------------------------------------


def test_http_ok_under_400_is_up() -> None:
    assert http_ok(200) is True
    assert http_ok(302) is True  # login redirect = box answered
    assert http_ok(399) is True
    assert http_ok(400) is False
    assert http_ok(500) is False


# --- run_probe combiner -----------------------------------------------------


async def test_run_probe_no_target_is_unprobed() -> None:
    result = await run_probe("")
    assert result == ProbeResult()
    assert result.probed is False


async def test_run_probe_url_runs_both_axes(monkeypatch) -> None:
    monkeypatch.setattr("app.probe.icmp.ping", lambda host, timeout=1.0: 4.2)

    async def fake_http(url, timeout=5.0):
        return True, 200

    monkeypatch.setattr("app.probe.http.http_probe", fake_http)

    result = await run_probe("https://10.20.1.198:4444")
    assert result.icmp_up is True
    assert result.rtt_ms == 4.2
    assert result.http_up is True
    assert result.http_status == 200
    assert result.probed is True


async def test_run_probe_bare_host_is_icmp_only(monkeypatch) -> None:
    monkeypatch.setattr("app.probe.icmp.ping", lambda host, timeout=1.0: None)
    result = await run_probe("10.20.1.198")
    assert result.icmp_up is False  # probed, no reply
    assert result.http_up is None  # not an http URL → HTTP not run
    assert result.probed is True
