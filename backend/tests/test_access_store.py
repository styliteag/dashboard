"""Access accounting + session registry (ADR docs/access-log.md).

DB-free house style: buffers and flush SQL are asserted directly, sessions are
fakes capturing statements. Also pins the admin gate on the audit/access read
surfaces (DR-AL1 — view_only must never read other users' IPs again).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from app.access import store


def _run(coro):
    return asyncio.run(coro)


def _reset():
    store._pending_agg.clear()
    store._pending_last_ip.clear()
    store._pending_events.clear()
    store._pending_seen.clear()
    store._seen_stamped.clear()
    return store


class _FakeResult:
    def __init__(self, rows=None):
        self._rows = rows or []
        self.rowcount = 0

    def all(self):
        return self._rows

    def scalars(self):
        return self

    def scalar(self):
        return self._rows[0] if self._rows else None

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


# --- record / buffers ------------------------------------------------------------


def test_record_counts_user_and_samples() -> None:
    _reset()
    store.record_request("user", "3", "10.0.0.9", "GET", "/api/instances", 200, user_id=3)
    assert store._pending_agg[("user", "3")] == 1
    assert store._pending_last_ip[("user", "3")] == "10.0.0.9"
    assert len(store._pending_events) == 1
    assert store._pending_events[0]["user_id"] == 3


def test_record_anon_aggregates_without_ip_or_sample() -> None:
    """DR-AL8: anonymous requests count, but leave no IP and no sample row."""
    _reset()
    store.record_request("anon", "anon", None, "GET", "/api/auth/me", 401)
    assert store._pending_agg[("anon", "anon")] == 1
    assert ("anon", "anon") not in store._pending_last_ip
    assert len(store._pending_events) == 0


def test_record_apikey_aggregates_only() -> None:
    _reset()
    store.record_apikey(7, "192.0.2.1")
    assert store._pending_agg[("apikey", "7")] == 1
    assert len(store._pending_events) == 0


def test_sample_buffer_bounded_but_aggregate_counts_all() -> None:
    """Flood behavior: row sample is capped, the aggregate never loses counts."""
    _reset()
    n = store._EVENTS_PER_FLUSH + 200
    for i in range(n):
        store.record_request("user", "3", "10.0.0.9", "GET", f"/api/x/{i}", 200, user_id=3)
    assert len(store._pending_events) == store._EVENTS_PER_FLUSH
    assert store._pending_agg[("user", "3")] == n


def test_last_seen_stamp_is_throttled(monkeypatch) -> None:
    """One last_seen write per session per throttle window — never per request."""
    _reset()
    clock = {"t": 1000.0}
    monkeypatch.setattr(store.time, "monotonic", lambda: clock["t"])
    store.record_request("user", "3", "1.1.1.1", "GET", "/api/a", 200, user_id=3, sid="s1")
    assert "s1" in store._pending_seen
    first = store._pending_seen["s1"]
    clock["t"] += 5  # within the window: no new stamp
    store.record_request("user", "3", "1.1.1.1", "GET", "/api/b", 200, user_id=3, sid="s1")
    assert store._pending_seen["s1"] is first
    clock["t"] += store._LAST_SEEN_THROTTLE_S  # window passed: stamped again
    store.record_request("user", "3", "1.1.1.1", "GET", "/api/c", 200, user_id=3, sid="s1")
    assert store._pending_seen["s1"] is not first


# --- flush -----------------------------------------------------------------------


def test_flush_upserts_and_clears() -> None:
    _reset()
    store.record_request("user", "3", "10.0.0.9", "GET", "/api/x", 200, user_id=3, sid="s1")
    store.record_request("user", "3", "10.0.0.9", "GET", "/api/y", 200, user_id=3)
    session = _FakeSession()
    n = _run(store.flush(session))
    assert n == 2
    # MariaDB-native upsert, never ON CONFLICT (repo rule).
    sql, params = session.executed[0]
    assert "ON DUPLICATE KEY UPDATE" in sql
    assert params["n"] == 2 and params["pkey"] == "3"
    assert len(session.added) == 2  # both sampled event rows
    # last_seen stamp for s1 flushed as an UPDATE on auth_sessions
    assert any("auth_sessions" in sql for sql, _ in session.executed[1:])
    assert not store._pending_agg and not store._pending_events and not store._pending_seen
    assert _run(store.flush(_FakeSession())) == 0  # idempotent when empty


# --- session registry --------------------------------------------------------------


def test_open_and_close_session() -> None:
    _reset()
    session = _FakeSession()
    _run(store.open_session(session, sid="abc", user_id=3, ip="1.2.3.4"))
    assert len(session.added) == 1
    row = session.added[0]
    assert row.sid == "abc" and row.user_id == 3 and row.ended_at is None
    _run(store.close_session(session, "abc", "logout"))
    assert any("auth_sessions" in sql for sql, _ in session.executed)
    # unknown/missing sid (pre-041 cookies) is a no-op, never an error
    before = len(session.executed)
    _run(store.close_session(session, None, "logout"))
    assert len(session.executed) == before


def test_expire_sessions_writes_audit_event() -> None:
    """DR-AL4: the silent 12h cookie death becomes auth.session_expired."""
    _reset()
    from app.db.models import AuditLog, AuthSession

    old = AuthSession(
        sid="s-old",
        user_id=3,
        ip="1.2.3.4",
        created_at=datetime.now(UTC) - timedelta(seconds=store.SESSION_MAX_AGE_S + 60),
        last_seen_at=datetime.now(UTC) - timedelta(hours=1),
    )

    class _ExpireSession(_FakeSession):
        async def execute(self, stmt, params=None):
            await super().execute(stmt, params)
            return _FakeResult(rows=[old])

    session = _ExpireSession()
    n = _run(store.expire_sessions(session))
    assert n == 1
    assert old.ended_at is not None and old.end_reason == "expired"
    audits = [a for a in session.added if isinstance(a, AuditLog)]
    assert len(audits) == 1
    assert audits[0].action == "auth.session_expired" and audits[0].user_id == 3


# --- middleware feed (_count_access routing) ---------------------------------------


def _feed(monkeypatch):
    from app import http_log

    calls: list[tuple] = []
    monkeypatch.setattr(
        http_log.access_store,
        "record_request",
        lambda *a, **k: calls.append((a, k)),
    )
    return http_log, calls


def test_count_access_routes_user_vs_anon(monkeypatch) -> None:
    http_log, calls = _feed(monkeypatch)
    scope_user = {"session": {"user_id": 3, "sid": "s1"}, "headers": []}
    http_log._count_access(scope_user, "1.1.1.1", "GET", "/api/instances", 200)
    scope_anon = {"session": {}, "headers": []}
    http_log._count_access(scope_anon, "2.2.2.2", "GET", "/api/auth/me", 401)
    assert calls[0][0][0] == "user" and calls[0][1]["sid"] == "s1"
    assert calls[1][0][0] == "anon"
    assert calls[1][0][2] is None  # DR-AL8: no anon IP


def test_count_access_skips_machine_and_denied_traffic(monkeypatch) -> None:
    """API-key scrapes are counted in read_principal, denials in the geoip
    store — counting them here again would double them (regression guard)."""
    http_log, calls = _feed(monkeypatch)
    # orbit_ bearer → counted via read_principal, not here
    scope_key = {
        "session": {},
        "headers": [(b"authorization", b"Bearer orbit_abc")],
    }
    http_log._count_access(scope_key, "1.1.1.1", "GET", "/api/checks/export", 200)
    # geoip/crowdsec denial → already in the denial store
    scope_denied = {"session": {}, "headers": [], "orbit.geoip_denied": True}
    http_log._count_access(scope_denied, "6.6.6.6", "GET", "/api/auth/login", 403)
    # agent traffic + health probes are not dashboard usage
    scope_agent = {"session": {}, "headers": []}
    http_log._count_access(scope_agent, "3.3.3.3", "WS", "/api/ws/agent", 101)
    http_log._count_access(scope_agent, "3.3.3.3", "GET", "/api/health", 200)
    # non-API (SPA assets) is not counted either
    http_log._count_access(scope_agent, "3.3.3.3", "GET", "/assets/app.js", 200)
    assert calls == []


# --- timeline search + grouped aggregation ------------------------------------------


def test_timeline_search_filters_all_sources() -> None:
    """q= must reach every source: audit (incl. the attempted username hidden
    in detail JSON on failed logins), denial events and request samples."""
    from app.access.routes import access_timeline

    session = _FakeSession()
    _run(
        access_timeline(
            session=session,
            _user=None,
            kinds="auth,denial,request",
            before=None,
            q="bonis",
            hours=24,
            limit=50,
        )
    )
    sqls = [sql for sql, _ in session.executed]
    # one username-resolve query + one per source
    assert any("users" in s and "LIKE" in s for s in sqls)
    audit_sql = next(s for s in sqls if "audit_log" in s)
    # generic compile renders the JSON path as detail[:param] (JSON_EXTRACT is
    # dialect-specific) — presence of the indexed access is what matters
    assert "LIKE" in audit_sql and "audit_log.detail[" in audit_sql
    assert "ts >=" in audit_sql  # hours window
    denial_sql = next(s for s in sqls if "geoip_denial_events" in s)
    assert "LIKE" in denial_sql
    request_sql = next(s for s in sqls if "access_events" in s)
    assert "LIKE" in request_sql


def test_access_kind_covers_instance_access_actions() -> None:
    """The "access" timeline kind must catch every instance-access audit
    action: web GUI, shell console, packet capture, firewall-rule edits."""
    from app.access.routes import _access_action_clause, access_timeline

    sql = str(_access_action_clause().compile(compile_kwargs={"literal_binds": True}))
    for prefix in ("agent.gui_open", "shell.", "capture.", "packet_capture.", "firewall.rule."):
        assert prefix in sql

    session = _FakeSession()
    _run(
        access_timeline(
            session=session,
            _user=None,
            kinds="access",
            before=None,
            q="opn1",
            hours=None,
            limit=50,
        )
    )
    sqls = [sql for sql, _ in session.executed]
    # searched by instance name too (resolve query against instances)
    assert any("instances" in s and "LIKE" in s for s in sqls)
    assert any("audit_log" in s for s in sqls)


def test_grouped_aggregates_per_source() -> None:
    """Logs-page pattern: GROUP BY per source, numeric path segments collapsed
    to one pattern per endpoint (regexp_replace) so ids don't explode rows."""
    from app.access.routes import access_grouped

    session = _FakeSession()
    result = _run(
        access_grouped(
            session=session,
            _user=None,
            kinds="auth,denial,request",
            q=None,
            hours=24,
            limit=100,
        )
    )
    assert result == []  # empty DB → empty list, no error
    sqls = [sql for sql, _ in session.executed]
    audit_sql = next(s for s in sqls if "audit_log" in s)
    assert "GROUP BY" in audit_sql and "count(" in audit_sql.lower()
    denial_sql = next(s for s in sqls if "geoip_denial_events" in s)
    assert "GROUP BY" in denial_sql
    request_sql = next(s for s in sqls if "access_events" in s)
    assert "GROUP BY" in request_sql and "regexp_replace" in request_sql.lower()


# --- admin gate on the read surfaces (DR-AL1) --------------------------------------


def test_audit_and_access_routes_are_admin_gated(monkeypatch) -> None:
    """Security fix 2026-07-14: /api/audit was current_user — any view_only
    account could read usernames, IPs and actions of everyone. Pin
    require_admin_or_superadmin (superadmin oversight stays included; its role
    is view_only) on it and every /api/access-log route so it cannot loosen."""
    monkeypatch.setattr("app.main.start_scheduler", lambda: None)

    from fastapi.routing import APIRoute

    from app.auth.deps import require_admin_or_superadmin
    from app.main import create_app

    def _calls(dependant):
        out, stack = set(), [dependant]
        while stack:
            dep = stack.pop()
            if getattr(dep, "call", None) is not None:
                out.add(dep.call)
            stack.extend(getattr(dep, "dependencies", []))
        return out

    app = create_app()
    checked = 0
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path == "/api/audit" or route.path.startswith("/api/access-log"):
            assert require_admin_or_superadmin in _calls(route.dependant), route.path
            checked += 1
    assert checked >= 3  # audit + summary + timeline


# --- GeoIP country enrichment on read surfaces (2026-07-16) --------------------------


class _RowSession(_FakeSession):
    """_FakeSession returning canned rows for selects matching a table marker.

    Count subqueries stay empty so pagination totals don't choke on ORM rows.
    """

    def __init__(self, rows_by_marker):
        super().__init__()
        self._rows_by_marker = rows_by_marker

    async def execute(self, stmt, params=None):
        sql = str(stmt)
        self.executed.append((sql, params))
        # Bare "SELECT count(*) FROM (...)" pagination totals stay empty;
        # GROUP-BY selects that merely contain count(*) still get their rows.
        if not sql.lstrip().lower().startswith("select count("):
            for marker, rows in self._rows_by_marker.items():
                if marker in sql:
                    return _FakeResult(rows)
        return _FakeResult()


def _patch_display(monkeypatch):
    """Stub the mmdb lookup: every IP resolves to DE with a full hover label."""
    from app.geoip import lookup

    monkeypatch.setattr(
        lookup,
        "country_display",
        lambda ip: ("DE", "Germany · Europe · EU") if ip else (None, None),
    )


def test_timeline_items_carry_country(monkeypatch) -> None:
    """Auth/access/request timeline rows resolve their IP through the local
    GeoIP DB so the UI shows origin everywhere an IP appears — not only on
    denial rows (which store their code at event time)."""
    from app.access.routes import access_timeline
    from app.db.models import AuditLog

    _patch_display(monkeypatch)
    row = AuditLog(ts=datetime.now(UTC), action="auth.login", result="ok", source_ip="203.0.113.7")
    session = _RowSession({"audit_log": [row]})
    page = _run(
        access_timeline(
            session=session,
            _user=None,
            kinds="auth",
            before=None,
            q=None,
            hours=None,
            limit=50,
        )
    )
    (item,) = page.items
    assert item.country == "DE"
    assert item.country_name == "Germany · Europe · EU"


def test_grouped_auth_rows_carry_country(monkeypatch) -> None:
    from app.access.routes import access_grouped

    _patch_display(monkeypatch)
    grow = ("auth.login", "ok", None, "203.0.113.7", 3, datetime.now(UTC))
    session = _RowSession({"audit_log": [grow]})
    (row,) = _run(
        access_grouped(session=session, _user=None, kinds="auth", q=None, hours=24, limit=100)
    )
    assert row.country == "DE"
    assert row.country_name == "Germany · Europe · EU"


def test_audit_entries_carry_country(monkeypatch) -> None:
    """/api/audit rows get source_country(+name) resolved from source_ip."""
    from app.audit.routes import list_audit
    from app.db.models import AuditLog

    _patch_display(monkeypatch)
    row = AuditLog(
        id=1,
        ts=datetime.now(UTC),
        action="settings.update",
        result="ok",
        source_ip="203.0.113.7",
    )
    session = _RowSession({"audit_log": [row]})
    page = _run(
        list_audit(
            page=1,
            page_size=50,
            action=None,
            instance_id=None,
            hours=None,
            session=session,
            _user=None,
        )
    )
    (entry,) = page.items
    assert entry.source_country == "DE"
    assert entry.source_country_name == "Germany · Europe · EU"
