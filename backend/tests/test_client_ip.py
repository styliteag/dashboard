"""Unit tests for trusted-proxy-aware client IP extraction (security F2)."""

import types

from app import net


class _Req:
    def __init__(self, xff=None, peer="9.9.9.9"):
        self.headers = {}
        if xff is not None:
            self.headers["x-forwarded-for"] = xff
        self.client = types.SimpleNamespace(host=peer) if peer else None


def _hops(monkeypatch, n):
    monkeypatch.setattr(net, "get_settings", lambda: types.SimpleNamespace(trusted_proxy_hops=n))


def test_zero_hops_ignores_xff(monkeypatch):
    # Bare deployment: never trust a client-supplied header.
    _hops(monkeypatch, 0)
    assert net.client_ip(_Req(xff="1.1.1.1", peer="9.9.9.9")) == "9.9.9.9"


def test_one_hop_returns_proxy_view_not_spoofed_prefix(monkeypatch):
    # nginx appends the real peer; an attacker who prepends "evil" can't win.
    _hops(monkeypatch, 1)
    assert net.client_ip(_Req(xff="evil, 5.5.5.5")) == "5.5.5.5"


def test_two_hops_picks_second_from_last(monkeypatch):
    _hops(monkeypatch, 2)
    assert net.client_ip(_Req(xff="evil, 7.7.7.7, 8.8.8.8")) == "7.7.7.7"


def test_hops_exceed_entries_falls_back_to_peer(monkeypatch):
    _hops(monkeypatch, 2)
    assert net.client_ip(_Req(xff="1.1.1.1", peer="9.9.9.9")) == "9.9.9.9"


def test_no_client_returns_unknown(monkeypatch):
    _hops(monkeypatch, 0)
    assert net.client_ip(_Req(xff=None, peer=None)) == "unknown"
