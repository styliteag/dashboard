"""GeoIP access restriction (docs/geoip-access-restriction.md).

Pure tests drive rules/decide directly; middleware tests use synthetic ASGI
scopes with the process caches monkeypatched — no DB, no real mmdb. The deny
tests assert the inner app was NEVER invoked (same discipline as the naked-WS
regression tests: an authz layer that calls through is a hole, not a bug).
"""

from __future__ import annotations

import asyncio
import gzip
import io
import tarfile
from types import SimpleNamespace

import pytest

import app.geoip.dyndns as dyndns
import app.geoip.middleware as mw
import app.net as net
from app.geoip.rules import (
    DISABLED,
    GeoipRules,
    classify_entry,
    decide,
    ip_whitelisted,
    parse_rules,
)
from app.geoip.updater import _extract_mmdb

# --- rules: entry classification ---------------------------------------------


def test_classify_cidr_v4_v6_and_single_ips() -> None:
    kind, net4 = classify_entry("10.0.0.0/8")
    assert kind == "cidr" and str(net4) == "10.0.0.0/8"
    kind, net6 = classify_entry("2001:db8::/32")
    assert kind == "cidr" and net6.version == 6
    kind, single = classify_entry("203.0.113.7")
    assert kind == "cidr" and str(single) == "203.0.113.7/32"
    kind, single6 = classify_entry("2001:db8::1")
    assert kind == "cidr" and str(single6) == "2001:db8::1/128"


def test_classify_hostname_and_garbage() -> None:
    assert classify_entry("host.dyndns.de") == ("hostname", "host.dyndns.de")
    assert classify_entry("Host.DynDNS.de")[1] == "host.dyndns.de"  # lowercased
    with pytest.raises(ValueError):
        classify_entry("not a hostname!")
    with pytest.raises(ValueError):
        classify_entry("barelabel")  # no dot: almost certainly a typo'd CIDR
    with pytest.raises(ValueError):
        classify_entry("")


def test_parse_rules_drops_bad_entries_instead_of_crashing() -> None:
    rules = parse_rules(True, '["de", "AT", "TOOLONG"]', '["10.0.0.0/8", "???", "h.dyn.de"]')
    assert rules.countries == frozenset({"DE", "AT"})
    assert len(rules.cidrs) == 1
    assert rules.hostnames == ("h.dyn.de",)
    # Broken JSON degrades to less-restrictive, never raises (middleware path!).
    broken = parse_rules(True, "{not json", "[42]")
    assert broken.countries == frozenset() and broken.cidrs == ()


# --- rules: decide (the DR-G3/G4/G5 contract) --------------------------------

_RULES_DE = GeoipRules(enabled=True, countries=frozenset({"DE"}))
_NO_RESOLVED = frozenset()


def test_empty_config_allows_all_even_when_enabled() -> None:
    """DR-G3: no countries + no whitelist = allow all — no first-boot lockout."""
    empty_but_enabled = GeoipRules(enabled=True)
    d = decide("8.8.8.8", empty_but_enabled, None, _NO_RESOLVED, db_available=True)
    assert d.allowed and d.reason == "not_restricting"
    assert not DISABLED.restricting


def test_country_allow_and_block() -> None:
    assert decide("1.2.3.4", _RULES_DE, "DE", _NO_RESOLVED, True).allowed
    denied = decide("1.2.3.4", _RULES_DE, "US", _NO_RESOLVED, True)
    assert not denied.allowed and denied.reason == "country_blocked"


def test_unknown_country_fails_closed() -> None:
    """Private/unlisted IPs have no country — with countries configured they
    are denied unless whitelisted (the documented LAN pitfall)."""
    denied = decide("10.1.2.3", _RULES_DE, None, _NO_RESOLVED, True)
    assert not denied.allowed and denied.reason == "no_country"


def test_missing_db_fails_open() -> None:
    """DR-G5: a broken/missing mmdb must not lock the whole company out."""
    d = decide("1.2.3.4", _RULES_DE, None, _NO_RESOLVED, db_available=False)
    assert d.allowed and d.reason == "db_unavailable"


def test_whitelist_cidr_v4_and_v6() -> None:
    rules = parse_rules(True, '["DE"]', '["192.168.0.0/16", "2001:db8::/32"]')
    assert decide("192.168.7.9", rules, None, _NO_RESOLVED, True).allowed
    assert decide("2001:db8::17", rules, None, _NO_RESOLVED, True).allowed
    assert not decide("192.169.0.1", rules, "US", _NO_RESOLVED, True).allowed


def test_whitelist_dyndns_resolved_ips() -> None:
    resolved = frozenset({"203.0.113.99", "2001:db8:beef::1"})
    assert decide("203.0.113.99", _RULES_DE, None, resolved, True).allowed
    assert decide("2001:db8:beef::1", _RULES_DE, None, resolved, True).allowed


def test_ip_whitelisted_mixed_versions_no_crash() -> None:
    rules = parse_rules(True, "[]", '["10.0.0.0/8"]')
    assert not ip_whitelisted("2001:db8::1", rules, frozenset())
    assert not ip_whitelisted("garbage", rules, frozenset())


# --- net: shared client-ip picker --------------------------------------------


def test_pick_client_ip_honours_hops_and_ignores_spoof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(net, "get_settings", lambda: SimpleNamespace(trusted_proxy_hops=1))
    # Attacker prepends a fake entry; with 1 trusted hop only the last counts.
    assert net.pick_client_ip("6.6.6.6, 203.0.113.7", "172.18.0.2") == "203.0.113.7"
    monkeypatch.setattr(net, "get_settings", lambda: SimpleNamespace(trusted_proxy_hops=0))
    assert net.pick_client_ip("6.6.6.6", "172.18.0.2") == "172.18.0.2"


# --- middleware: scope evaluation --------------------------------------------


def _scope(
    path: str = "/api/instances",
    *,
    typ: str = "http",
    headers: list[tuple[bytes, bytes]] | None = None,
    client: tuple[str, int] | None = ("198.51.100.10", 1234),
) -> dict:
    return {"type": typ, "path": path, "headers": headers or [], "client": client}


@pytest.fixture()
def enforcing(monkeypatch: pytest.MonkeyPatch):
    """Middleware sees: enforcement on (DE only), mmdb present, US caller."""
    monkeypatch.setattr(mw, "current_rules", lambda: _RULES_DE)
    monkeypatch.setattr(
        mw, "get_settings", lambda: SimpleNamespace(geoip_disable=False, trusted_proxy_hops=0)
    )
    monkeypatch.setattr(net, "get_settings", lambda: SimpleNamespace(trusted_proxy_hops=0))
    monkeypatch.setattr(mw.lookup, "db_available", lambda: True)
    monkeypatch.setattr(mw.lookup, "country_for", lambda ip: "US")
    monkeypatch.setattr(mw.dyndns, "resolved_ips", frozenset)
    mw._last_logged.clear()


def test_scope_denied_for_blocked_country(enforcing) -> None:
    allowed, reason, ip, country = mw.evaluate_scope(_scope())
    assert not allowed and reason == "country_blocked"
    assert ip == "198.51.100.10" and country == "US"


def test_scope_exemptions(enforcing) -> None:
    # Agent WS + tunnel + enroll + health: firewalls connect from anywhere.
    for path in ("/api/ws/agent", "/api/ws/tunnel/5", "/api/agent/enroll", "/api/health"):
        assert mw.evaluate_scope(_scope(path))[0], path
    # Non-/api (static SPA bundle) is not the middleware's business.
    assert mw.evaluate_scope(_scope("/assets/index.js"))[0]
    # orbit_ API keys are machine reads — exempt (DR-G2).
    ok, reason, _, _ = mw.evaluate_scope(
        _scope(headers=[(b"authorization", b"Bearer orbit_abc123")])
    )
    assert ok and reason == "api_key"
    # But a session Bearer token is NOT exempt.
    assert not mw.evaluate_scope(_scope(headers=[(b"authorization", b"Bearer xyz")]))[0]


def test_scope_kill_switch_overrides_everything(enforcing, monkeypatch) -> None:
    monkeypatch.setattr(
        mw, "get_settings", lambda: SimpleNamespace(geoip_disable=True, trusted_proxy_hops=0)
    )
    assert mw.evaluate_scope(_scope())[0]


def test_scope_user_ws_is_enforced(enforcing) -> None:
    """/ws/shell etc. are user-facing — geo applies (only agent WS is exempt)."""
    assert not mw.evaluate_scope(_scope("/api/ws/shell/3", typ="websocket"))[0]


# --- middleware: ASGI behavior on deny ----------------------------------------


def _run(coro):
    return asyncio.run(coro)


def test_denied_http_gets_403_and_never_reaches_app(enforcing, monkeypatch) -> None:
    inner_called = []

    async def inner(scope, receive, send):
        inner_called.append(scope["path"])

    audited = []

    async def fake_audit(ip, country, reason):
        audited.append((ip, country, reason))

    middleware = mw.GeoipMiddleware(inner)
    monkeypatch.setattr(middleware, "_audit_login_denial", fake_audit)
    sent = []

    async def send(message):
        sent.append(message)

    _run(middleware(_scope(), None, send))
    assert not inner_called  # the whole point: deny means the app never runs
    assert sent[0]["status"] == 403
    assert b"access restricted from your location" in sent[1]["body"]
    assert not audited  # non-login paths are logged, not audited


def test_denied_login_is_audited(enforcing, monkeypatch) -> None:
    async def inner(scope, receive, send):  # pragma: no cover — must not run
        raise AssertionError("reached app despite deny")

    audited = []

    async def fake_audit(ip, country, reason):
        audited.append((ip, country, reason))

    middleware = mw.GeoipMiddleware(inner)
    monkeypatch.setattr(middleware, "_audit_login_denial", fake_audit)

    async def send(message):
        pass

    _run(middleware(_scope("/api/auth/login"), None, send))
    assert audited == [("198.51.100.10", "US", "country_blocked")]


def test_denied_websocket_closes_before_accept(enforcing) -> None:
    async def inner(scope, receive, send):  # pragma: no cover
        raise AssertionError("reached app despite deny")

    sent = []

    async def send(message):
        sent.append(message)

    _run(mw.GeoipMiddleware(inner)(_scope("/api/ws/shell/1", typ="websocket"), None, send))
    assert sent == [{"type": "websocket.close", "code": 4403}]


def test_allowed_request_passes_through(enforcing, monkeypatch) -> None:
    monkeypatch.setattr(mw.lookup, "country_for", lambda ip: "DE")
    passed = []

    async def inner(scope, receive, send):
        passed.append(scope["path"])

    _run(mw.GeoipMiddleware(inner)(_scope(), None, lambda m: None))
    assert passed == ["/api/instances"]


# --- dyndns: failure keeps last known IPs -------------------------------------


def test_dyndns_failure_keeps_previous_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    dyndns._state.clear()

    async def resolve_ok(host):
        return frozenset({"203.0.113.5"})

    monkeypatch.setattr(dyndns, "_resolve_one", resolve_ok)
    _run(dyndns.refresh(("host.dyndns.de",)))
    assert dyndns.resolved_ips() == frozenset({"203.0.113.5"})

    async def resolve_fail(host):
        raise OSError("temporary failure in name resolution")

    monkeypatch.setattr(dyndns, "_resolve_one", resolve_fail)
    _run(dyndns.refresh(("host.dyndns.de",)))
    # DR-G4: flapping DNS must not lock out — old address survives, error shown.
    assert dyndns.resolved_ips() == frozenset({"203.0.113.5"})
    assert dyndns.snapshot()[0]["error"]


def test_dyndns_removed_hostname_forgotten(monkeypatch: pytest.MonkeyPatch) -> None:
    dyndns._state.clear()

    async def resolve_ok(host):
        return frozenset({"203.0.113.6"})

    monkeypatch.setattr(dyndns, "_resolve_one", resolve_ok)
    _run(dyndns.refresh(("gone.dyndns.de",)))
    _run(dyndns.refresh(()))
    assert dyndns.resolved_ips() == frozenset()


# --- updater: tarball extraction ----------------------------------------------


def test_extract_mmdb_from_tarball() -> None:
    payload = b"\x00mmdb-bytes\x00"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("GeoLite2-Country_20260710/GeoLite2-Country.mmdb")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    assert _extract_mmdb(buf.getvalue()) == payload


def test_extract_mmdb_missing_member_raises() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("README.txt")
        info.size = 2
        tar.addfile(info, io.BytesIO(b"hi"))
    with pytest.raises(ValueError):
        _extract_mmdb(buf.getvalue())


def test_gzip_import_unused_guard() -> None:
    # keep ruff happy about the gzip import used only via tarfile's mode above
    assert gzip.compress(b"x")
