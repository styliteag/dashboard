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
    # GUI-proxy forward_auth/handoff subrequests arrive container-to-container —
    # the peer is the proxy's docker IP (no country). Prod incident 2026-07-14:
    # every GUI open was denied with no_country. Auth happens in the endpoints
    # themselves (one-time token / per-instance HMAC cookie).
    for path in ("/api/gui/authcheck", "/api/gui/handoff"):
        assert mw.evaluate_scope(_scope(path))[0], path
    # ...but the rest of /api/gui/ stays geo-gated (user-facing session routes).
    assert not mw.evaluate_scope(_scope("/api/instances/3/gui/open"))[0]
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


# --- crowdsec: decide integration (DR-G8) --------------------------------------


def _ban(*ips: str):
    banned = set(ips)
    return lambda ip: ip in banned


def test_banned_ip_denied_even_without_country_restriction() -> None:
    """The blocklist has its own switch — it must bite with GeoIP off."""
    d = decide("6.6.6.6", DISABLED, None, _NO_RESOLVED, True, banned=_ban("6.6.6.6"))
    assert not d.allowed and d.reason == "crowdsec_banned"


def test_whitelist_beats_blocklist() -> None:
    """Operator rescue first: a whitelisted IP passes despite an active ban."""
    rules = parse_rules(True, '["DE"]', '["203.0.113.0/24"]')
    d = decide("203.0.113.7", rules, None, _NO_RESOLVED, True, banned=_ban("203.0.113.7"))
    assert d.allowed and d.reason == "whitelisted"


def test_blocklist_beats_country_allow() -> None:
    d = decide("1.2.3.4", _RULES_DE, "DE", _NO_RESOLVED, True, banned=_ban("1.2.3.4"))
    assert not d.allowed and d.reason == "crowdsec_banned"


def test_no_banned_callable_keeps_old_behavior() -> None:
    assert decide("6.6.6.6", DISABLED, None, _NO_RESOLVED, True).allowed


# --- crowdsec: state transitions + sync ----------------------------------------


def _cs_reset():
    import app.geoip.crowdsec as cs

    cs._banned_ips.clear()
    cs._banned_ranges.clear()
    cs._last.update(at=None, ok=None, detail="never synced")
    return cs


def test_crowdsec_apply_decisions_and_ranges() -> None:
    cs = _cs_reset()
    cs.apply_decisions(
        new=[
            {"type": "ban", "value": "6.6.6.6"},
            {"type": "ban", "value": "198.51.100.0/24"},
            {"type": "ban", "value": "2001:db8:bad::/48"},
            {"type": "captcha", "value": "9.9.9.9"},  # non-ban ignored
            {"type": "ban", "value": "garbage"},  # junk ignored
        ],
        deleted=[],
    )
    assert cs.is_banned("6.6.6.6")
    assert cs.is_banned("198.51.100.77")
    assert cs.is_banned("2001:db8:bad::1")
    assert not cs.is_banned("9.9.9.9")
    assert cs.banned_count() == 3
    cs.apply_decisions(new=[], deleted=[{"type": "ban", "value": "6.6.6.6"}])
    assert not cs.is_banned("6.6.6.6")


def test_crowdsec_sync_failure_keeps_bans(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stale beats empty: a LAPI outage must not un-ban every attacker."""
    import httpx as _httpx
    import respx

    import app.geoip.crowdsec as cs

    _cs_reset()
    cs.apply_decisions(new=[{"type": "ban", "value": "6.6.6.6"}], deleted=[])
    monkeypatch.setattr(
        cs,
        "get_settings",
        lambda: SimpleNamespace(
            crowdsec_disable=False,
            crowdsec_api_key="k",
            crowdsec_lapi_url="http://lapi.test:8080",
        ),
    )
    with respx.mock:
        respx.get("http://lapi.test:8080/v1/decisions/stream").mock(
            side_effect=_httpx.ConnectError("down")
        )
        _run(cs.sync())
    assert cs.is_banned("6.6.6.6")
    assert cs.status()["ok"] is False


def test_crowdsec_sync_applies_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    import respx

    import app.geoip.crowdsec as cs

    _cs_reset()
    monkeypatch.setattr(cs, "_startup_done", False)
    monkeypatch.setattr(
        cs,
        "get_settings",
        lambda: SimpleNamespace(
            crowdsec_disable=False,
            crowdsec_api_key="k",
            crowdsec_lapi_url="http://lapi.test:8080",
        ),
    )
    with respx.mock:
        route = respx.get("http://lapi.test:8080/v1/decisions/stream").respond(
            json={"new": [{"type": "ban", "value": "6.6.6.7"}], "deleted": None}
        )
        _run(cs.sync())
    assert route.calls[0].request.url.params["startup"] == "true"
    assert cs.is_banned("6.6.6.7")
    assert cs.status()["ok"] is True


def test_middleware_denies_crowdsec_banned_ip(enforcing, monkeypatch) -> None:
    """Banned peer gets 403 without the app ever running — even though its
    country (DE) is on the allowlist."""
    monkeypatch.setattr(mw.lookup, "country_for", lambda ip: "DE")
    monkeypatch.setattr(mw.crowdsec, "active", lambda: True)
    monkeypatch.setattr(mw.crowdsec, "is_banned", lambda ip: ip == "198.51.100.10")
    allowed, reason, ip, _ = mw.evaluate_scope(_scope())
    assert not allowed and reason == "crowdsec_banned" and ip == "198.51.100.10"


def test_middleware_blocklist_without_country_restriction(enforcing, monkeypatch) -> None:
    monkeypatch.setattr(mw, "current_rules", lambda: DISABLED)
    monkeypatch.setattr(mw.crowdsec, "active", lambda: True)
    monkeypatch.setattr(mw.crowdsec, "is_banned", lambda ip: True)
    assert not mw.evaluate_scope(_scope())[0]
    # Blocklist off again: GeoIP disabled → everything passes.
    monkeypatch.setattr(mw.crowdsec, "active", lambda: False)
    assert mw.evaluate_scope(_scope())[0]


# --- denials accounting (persistent two-tier design, migration 040) -------------


def _den_reset():
    import app.geoip.denials as den

    den._pending_agg.clear()
    den._pending_events.clear()
    den._totals.clear()
    den._total_countries.clear()
    den._total_fail_open = 0
    return den


class _FakeResult:
    def __init__(self, rows=None):
        self._rows = rows or []
        self.rowcount = 0

    def all(self):
        return self._rows

    def scalars(self):
        return self

    def first(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    """Captures executed statements; returns empty results (DB-free house style)."""

    def __init__(self):
        self.executed: list[tuple[str, dict | None]] = []
        self.added: list[object] = []

    async def execute(self, stmt, params=None):
        self.executed.append((str(stmt), params))
        return _FakeResult()

    async def scalar(self, stmt):
        return None

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def commit(self):
        pass


def test_denials_record_feeds_buffers_and_mirrors() -> None:
    den = _den_reset()
    den.record("1.2.3.4", "US", "/api/auth/login", "country_blocked")
    den.record("6.6.6.6", None, "/api/instances", "crowdsec_banned")
    den.record_fail_open()
    assert den._pending_agg[("country_blocked", "US")] == 1
    assert den._pending_agg[("crowdsec_banned", "??")] == 1
    by_reason, by_country, fail_open = den.prometheus_series()
    assert by_reason == {"country_blocked": 1, "crowdsec_banned": 1}
    assert by_country == {"US": 1, "??": 1}
    assert fail_open == 1


def test_denials_event_buffer_bounded_but_aggregate_counts_all() -> None:
    """Flood behavior: row sample is capped, the aggregate never loses counts."""
    den = _den_reset()
    for i in range(den._EVENTS_PER_FLUSH + 200):
        den.record(f"10.0.0.{i % 250}", None, "/api/x", "no_country")
    assert len(den._pending_events) == den._EVENTS_PER_FLUSH
    assert den._pending_agg[("no_country", "??")] == den._EVENTS_PER_FLUSH + 200


def test_denials_flush_upserts_and_clears(monkeypatch) -> None:
    den = _den_reset()
    den.record("1.2.3.4", "US", "/api/x", "country_blocked")
    den.record("1.2.3.4", "US", "/api/y", "country_blocked")
    session = _FakeSession()
    n = _run(den.flush(session))
    assert n == 2
    # MariaDB-native upsert, never ON CONFLICT (repo rule).
    sql, params = session.executed[0]
    assert "ON DUPLICATE KEY UPDATE" in sql and params["n"] == 2
    assert len(session.added) == 2  # both sampled event rows
    assert not den._pending_agg and not den._pending_events  # buffers swapped out
    assert _run(den.flush(_FakeSession())) == 0  # idempotent when empty


def test_denials_hydrate_restores_prometheus_mirrors() -> None:
    den = _den_reset()

    class _HydrateSession(_FakeSession):
        async def execute(self, stmt, params=None):
            return _FakeResult(rows=[("country_blocked", "US", 41), ("fail_open", "??", 3)])

    _run(den.hydrate(_HydrateSession()))
    by_reason, by_country, fail_open = den.prometheus_series()
    assert by_reason["country_blocked"] == 41  # restart is NOT a counter reset
    assert by_country["US"] == 41
    assert fail_open == 3


def test_denials_snapshot_folds_pending_into_empty_db() -> None:
    den = _den_reset()
    den.record("1.2.3.4", "US", "/api/x", "country_blocked")
    snap = _run(den.snapshot(_FakeSession(), limit=10))
    assert snap["total"] == 1
    assert snap["by_reason"] == {"country_blocked": 1}
    assert snap["recent"][0]["ip"] == "1.2.3.4"  # visible before the 15s flush


def test_middleware_deny_records_denial(enforcing, monkeypatch) -> None:
    den = _den_reset()

    async def inner(scope, receive, send):  # pragma: no cover
        raise AssertionError("reached app despite deny")

    async def send(message):
        pass

    middleware = mw.GeoipMiddleware(inner)
    monkeypatch.setattr(middleware, "_audit_login_denial", lambda *a: None)
    _run(middleware(_scope(), None, send))
    assert den._pending_agg[("country_blocked", "US")] == 1
    assert den._pending_events[0]["ip"] == "198.51.100.10"


def test_prometheus_denial_counters_render() -> None:
    from app.checks.prometheus import render_geoip_denials

    den = _den_reset()
    assert render_geoip_denials() == ""  # all zero -> no families emitted
    den.record("1.2.3.4", "US", "/api/x", "country_blocked")
    text = render_geoip_denials()
    assert "# TYPE orbit_geoip_denied_total counter" in text
    assert 'orbit_geoip_denied_total{reason="country_blocked"} 1' in text
    assert 'orbit_geoip_denied_country_total{country="US"} 1' in text


def test_denials_summary_totals_only() -> None:
    """The every-user summary exposes ONLY the aggregate number — no IPs,
    countries or paths (those stay superadmin-only in /denials)."""
    import asyncio as _asyncio

    from app.geoip.routes import geoip_denials_summary

    den = _den_reset()
    den.record("1.2.3.4", "US", "/api/x", "country_blocked")
    den.record("6.6.6.6", None, "/api/y", "crowdsec_banned")
    result = _asyncio.run(geoip_denials_summary(None))
    assert result == {"total": 2}


# --- lookup: country_display (UI enrichment, 2026-07-16) ----------------------


class _FakeReader:
    def __init__(self, record):
        self._record = record

    def get(self, ip):
        if ip == "malformed":
            raise ValueError("bad ip")
        return self._record


def test_country_display_full_record(monkeypatch) -> None:
    """Everything the GeoLite2-City DB knows lands in the hover label: city,
    most-specific subdivision, English name, continent, EU membership."""
    import app.geoip.lookup as lookup

    record = {
        "city": {"names": {"en": "Frankfurt am Main"}},
        # largest→smallest per MaxMind; the last one is the state we want
        "subdivisions": [{"names": {"en": "Hesse"}}],
        "country": {
            "iso_code": "DE",
            "names": {"en": "Germany", "de": "Deutschland"},
            "is_in_european_union": True,
        },
        "continent": {"names": {"en": "Europe"}},
    }
    monkeypatch.setattr(lookup, "_current_reader", lambda: _FakeReader(record))
    assert lookup.country_display("203.0.113.7") == (
        "DE",
        "Frankfurt am Main, Hesse · Germany · Europe · EU",
    )


def test_country_display_plain_country_db(monkeypatch) -> None:
    """A volume still holding the old Country edition (no city/subdivisions)
    keeps working — the label simply has no place prefix."""
    import app.geoip.lookup as lookup

    record = {
        "country": {
            "iso_code": "DE",
            "names": {"en": "Germany"},
            "is_in_european_union": True,
        },
        "continent": {"names": {"en": "Europe"}},
    }
    monkeypatch.setattr(lookup, "_current_reader", lambda: _FakeReader(record))
    assert lookup.country_display("203.0.113.7") == ("DE", "Germany · Europe · EU")


def test_country_display_degrades_gracefully(monkeypatch) -> None:
    """Missing pieces never break display: bare code fallback, None for
    missing DB / None IP / malformed IP / private ranges (no record)."""
    import app.geoip.lookup as lookup

    monkeypatch.setattr(
        lookup, "_current_reader", lambda: _FakeReader({"country": {"iso_code": "US"}})
    )
    assert lookup.country_display("198.51.100.1") == ("US", "US")
    assert lookup.country_display(None) == (None, None)
    assert lookup.country_display("malformed") == (None, None)

    monkeypatch.setattr(lookup, "_current_reader", lambda: _FakeReader(None))
    assert lookup.country_display("10.0.0.1") == (None, None)  # private: no record

    monkeypatch.setattr(lookup, "_current_reader", lambda: None)
    assert lookup.country_display("198.51.100.1") == (None, None)  # DB missing
