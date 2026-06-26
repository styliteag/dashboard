"""Tests for cross-instance tunnel pairing in the global VPN overview."""

from __future__ import annotations

from app.views.routes import GlobalTunnel, _attach_peers


def _t(**kw) -> GlobalTunnel:
    base = dict(
        instance_id=1,
        instance_name="x",
        tunnel_id="t",
        unique_id="",
        description="",
        remote="",
        local="",
        phase1_status="ESTABLISHED",
        phase2_up=1,
        phase2_total=1,
        seconds_established=1,
        bytes_in=0,
        bytes_out=0,
    )
    base.update(kw)
    return GlobalTunnel(**base)


def test_pairs_by_ike_spi() -> None:
    a = _t(instance_id=1, instance_name="opn1", tunnel_id="a", ike_init_spi="AA", ike_resp_spi="BB")
    b = _t(instance_id=2, instance_name="opn2", tunnel_id="b", ike_init_spi="AA", ike_resp_spi="BB")
    _attach_peers([a, b])
    assert a.peer_instance_name == "opn2" and a.peer_tunnel_id == "b"
    assert b.peer_instance_name == "opn1" and b.peer_tunnel_id == "a"


def test_ike_spi_wins_over_ip_when_present() -> None:
    # IPs would mismatch, but SPI pairs them anyway (NAT case).
    a = _t(
        instance_id=1,
        instance_name="opn1",
        local="203.0.113.1",
        remote="198.51.100.9",
        ike_init_spi="AA",
        ike_resp_spi="BB",
    )
    b = _t(
        instance_id=2,
        instance_name="opn2",
        local="10.0.0.2",
        remote="10.0.0.1",
        ike_init_spi="AA",
        ike_resp_spi="BB",
    )
    _attach_peers([a, b])
    assert a.peer_instance_id == 2 and b.peer_instance_id == 1


def test_falls_back_to_reversed_ip_when_no_spi() -> None:
    # Down tunnels have no SPI → pair by reversed transport-IP pair.
    a = _t(
        instance_id=1,
        instance_name="opn1",
        local="10.21.7.100",
        remote="10.21.7.101",
        phase1_status="down",
    )
    b = _t(
        instance_id=2,
        instance_name="opn2",
        local="10.21.7.101",
        remote="10.21.7.100",
        phase1_status="down",
    )
    _attach_peers([a, b])
    assert a.peer_instance_id == 2 and b.peer_instance_id == 1


def test_no_peer_for_external_remote() -> None:
    a = _t(
        instance_id=1,
        instance_name="opn1",
        local="10.21.7.100",
        remote="2.2.2.2",
        ike_init_spi="AA",
        ike_resp_spi="BB",
    )
    _attach_peers([a])
    assert a.peer_instance_id is None


def test_does_not_pair_tunnel_with_itself() -> None:
    a = _t(instance_id=1, local="10.0.0.1", remote="10.0.0.1", ike_init_spi="AA", ike_resp_spi="BB")
    _attach_peers([a])
    assert a.peer_instance_id is None
