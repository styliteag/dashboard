"""Parse real ``swanctl --raw`` output captured from a Securepoint UTM 14.1.6 box.

The SAS fixture deliberately contains the established SA *and* a passive ``%any``
half-open responder SA under the same connection name — the case that collapses
into a Frankenstein record without the disambiguation fix.
"""

from __future__ import annotations

from app.securepoint.swanctl import _unescape_conn_name, parse_ipsec

# Two `list-sa event {bonis-test {...}}` envelopes: uniqueid=3 ESTABLISHED (real)
# and uniqueid=1 CREATED/%any (half-open). Plus the trailing `reply {}`.
_SAS_RAW = (
    "list-sa event {bonis-test {uniqueid=3 version=2 state=ESTABLISHED "
    "local-host=213.232.100.192 local-port=4500 local-id=sp-bensheim.spdns.de "
    "remote-host=84.180.80.50 remote-port=56069 remote-id=kl.bonis.de initiator=yes "
    "initiator-spi=0731875234fa6144 responder-spi=0f1186ba1485124f nat-remote=yes "
    "encr-alg=AES_CBC encr-keysize=256 established=556 rekey-time=6187 child-sas "
    "{bonis-test-7 {name=bonis-test uniqueid=7 reqid=2 state=INSTALLED mode=TUNNEL "
    "protocol=ESP spi-in=c8d53263 spi-out=cd2f7951 bytes-in=0 packets-in=0 bytes-out=0 "
    "packets-out=0 local-ts=[10.21.0.0/22] remote-ts=[10.99.1.0/24]} "
    "bonis-test-8 {name=bonis-test uniqueid=8 reqid=1 state=INSTALLED mode=TUNNEL "
    "protocol=ESP spi-in=cc619d6b spi-out=ccda13c7 bytes-in=146580 packets-in=1745 "
    "bytes-out=80976 packets-out=964 local-ts=[10.21.0.0/22] remote-ts=[10.1.1.0/24]}}}}\n"
    "list-sa event {bonis-test {uniqueid=1 version=2 state=CREATED local-host=%any "
    "local-port=500 local-id=%any remote-host=%any remote-port=500 remote-id=%any "
    "initiator=yes initiator-spi=ca3f9bef87c9c0d6 responder-spi=0000000000000000 "
    "child-sas {}}}\nlist-sas reply {}\n"
)
_CONNS_RAW = (
    "list-conn event {bonis-test {local_addrs=[%any] remote_addrs=[%any] version=IKEv2 "
    "rekey_time=7200 children {bonis-test {mode=TUNNEL local-ts=[10.21.0.0/22] "
    "remote-ts=[10.1.1.0/24 10.99.1.0/24]}}}}\nlist-conns reply {}\n"
)


def test_parse_drops_half_open_and_keeps_established_with_spis() -> None:
    tunnels = parse_ipsec(_SAS_RAW, _CONNS_RAW)

    assert len(tunnels) == 1  # the %any half-open is dropped, not merged
    t = tunnels[0]
    assert t.id == "bonis-test"
    assert t.phase1_status == "ESTABLISHED"
    assert t.local == "213.232.100.192"  # NOT clobbered to %any
    assert t.remote == "84.180.80.50"
    # IKE cookie pair — the NAT-proof key that pairs with the opn1 end.
    assert t.ike_init_spi == "0731875234fa6144"
    assert t.ike_resp_spi == "0f1186ba1485124f"
    assert (t.phase2_up, t.phase2_total) == (2, 2)
    assert t.bytes_in == 146580 and t.bytes_out == 80976
    # ESP SPIs per child (A.spi_out == B.spi_in across ends).
    by_remote = {c.remote_ts: c for c in t.children}
    assert by_remote["10.1.1.0/24"].spi_in == "cc619d6b"
    assert by_remote["10.1.1.0/24"].spi_out == "ccda13c7"
    assert by_remote["10.99.1.0/24"].spi_in == "c8d53263"
    assert all(c.state == "INSTALLED" for c in t.children)


def test_empty_input_yields_no_tunnels() -> None:
    assert parse_ipsec("", "") == []
    assert parse_ipsec("list-sas reply {}\n", "list-conns reply {}\n") == []


# --- Securepoint $XX connection-name unescaping (display name) -----------------
# Securepoint hex-escapes characters invalid in a strongSwan section id; the swanctl
# name `Broken$20Connection` must show as "Broken Connection" while the raw form
# stays the tunnel id (swanctl --ike expects it). Confirmed live on the bensheim box.


def test_unescape_decodes_space() -> None:
    assert _unescape_conn_name("Broken$20Connection") == "Broken Connection"
    assert _unescape_conn_name("Vendor$20Tunnel$20IKEv2") == "Vendor Tunnel IKEv2"
    assert _unescape_conn_name("KC$20RM$20OPNSE") == "KC RM OPNSE"


def test_unescape_passthrough_when_no_escape() -> None:
    assert _unescape_conn_name("bonis-test") == "bonis-test"
    assert _unescape_conn_name("TI") == "TI"
    assert _unescape_conn_name("") == ""


def test_unescape_multibyte_utf8_roundtrips() -> None:
    # an umlaut escaped as its UTF-8 bytes ($C3$BC = ü) must reassemble, not split
    assert _unescape_conn_name("M$C3$BCller$20VPN") == "Müller VPN"


def test_unescape_leaves_non_hex_and_partial_dollar_literal() -> None:
    assert _unescape_conn_name("cost$ZZplan") == "cost$ZZplan"  # $ZZ is not hex
    assert _unescape_conn_name("trailing$2") == "trailing$2"  # only one hex digit
    assert _unescape_conn_name("bare$") == "bare$"


def test_to_tunnel_keeps_raw_id_and_decodes_description() -> None:
    conns = (
        "list-conn event {Broken$20Connection {local_addrs=[%any] remote_addrs=[1.2.3.4] "
        "children {c1 {mode=TUNNEL local-ts=[10.0.0.0/24] remote-ts=[10.1.0.0/24]}}}}"
    )
    tunnels = parse_ipsec("", conns)
    assert len(tunnels) == 1
    t = tunnels[0]
    assert t.id == "Broken$20Connection"  # raw — swanctl --ike / slicing need it verbatim
    assert t.description == "Broken Connection"  # decoded — what the UI shows
