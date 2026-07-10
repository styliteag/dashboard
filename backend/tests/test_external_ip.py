"""External-IP section: converter, lip-mismatch annotation, and the scoped route.

DB-free house style: pure converters plus a TestClient drive of the route with the
instance fetch + hub monkeypatched (no MariaDB, no live agent).
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

import app.main as main_mod
import app.metrics.routes as metrics_mod
from app.agent_hub.converters import (
    _local_ip_mismatch,
    annotate_local_ip_mismatch,
    external_ip_from_agent,
)
from app.auth.deps import current_user
from app.db.base import get_session
from app.xsense.schemas import (
    ExternalIp,
    InterfaceStats,
    IPsecServiceStatus,
    IPsecTunnel,
    SystemStatus,
)

# --- converter: external_ip_from_agent --------------------------------------


def test_external_ip_from_agent_parses_both_families() -> None:
    ext = external_ip_from_agent(
        {"external_ip": {"ipv4": "203.0.113.7", "ipv6": "2001:db8::1", "checked_at": "t"}}
    )
    assert ext is not None
    assert ext.ipv4 == "203.0.113.7"
    assert ext.ipv6 == "2001:db8::1"


def test_external_ip_from_agent_none_when_absent() -> None:
    # Older agent that never sends the section → None, so the cache is kept.
    assert external_ip_from_agent({}) is None
    assert external_ip_from_agent({"external_ip": "not-a-dict"}) is None


def test_external_ip_from_agent_allows_both_none() -> None:
    # A modern agent whose probes both failed sends an all-None section — that is a
    # valid ExternalIp (distinct from "section absent"); the hub guard drops it.
    ext = external_ip_from_agent({"external_ip": {"ipv4": None, "ipv6": None}})
    assert ext is not None
    assert ext.ipv4 is None and ext.ipv6 is None


# --- lip-mismatch logic ------------------------------------------------------


# NB: uses genuinely globally-routable IPs — RFC-5737 (203.0.113.x) and RFC-3849
# (2001:db8::) documentation ranges are is_global=False, so the public-local gate
# would (correctly) skip them and the mismatch could never fire.
def test_local_ip_mismatch_flags_stale_public_local() -> None:
    # Tunnel pinned to a public IP that is not the box's current external IP.
    assert _local_ip_mismatch("8.8.8.8", "9.9.9.9", None) is True


def test_local_ip_mismatch_clear_when_local_equals_external() -> None:
    assert _local_ip_mismatch("8.8.8.8", "8.8.8.8", None) is False


def test_local_ip_mismatch_ignores_private_local() -> None:
    # A private local endpoint is the normal behind-NAT / NAT-T case → not a note.
    assert _local_ip_mismatch("192.168.1.2", "9.9.9.9", None) is False


def test_local_ip_mismatch_ignores_non_ip_local() -> None:
    # "%any", an interface name or empty is nothing to compare.
    assert _local_ip_mismatch("%any", "9.9.9.9", None) is False
    assert _local_ip_mismatch("", "9.9.9.9", None) is False


def test_local_ip_mismatch_off_when_external_unknown() -> None:
    # Can't compare v4 local without a known v4 external → default off, don't guess.
    assert _local_ip_mismatch("8.8.8.8", None, "2606:4700:4700::1111") is False


def test_local_ip_mismatch_uses_matching_family() -> None:
    assert _local_ip_mismatch("2606:4700:4700::1111", "9.9.9.9", "2606:4700:4700::1001") is True
    assert _local_ip_mismatch("2606:4700:4700::1111", "9.9.9.9", "2606:4700:4700::1111") is False


def _tunnel(local: str) -> IPsecServiceStatus:
    return IPsecServiceStatus(running=True, tunnels=[IPsecTunnel(id="t1", local=local)])


def test_annotate_sets_flag_on_mismatch() -> None:
    ext = ExternalIp(ipv4="9.9.9.9")
    out = annotate_local_ip_mismatch(_tunnel("8.8.8.8"), ext)
    assert out.tunnels[0].local_ip_mismatch is True


def test_annotate_clears_flag_when_matching() -> None:
    ext = ExternalIp(ipv4="8.8.8.8")
    out = annotate_local_ip_mismatch(_tunnel("8.8.8.8"), ext)
    assert out.tunnels[0].local_ip_mismatch is False


def test_annotate_off_when_no_external() -> None:
    out = annotate_local_ip_mismatch(_tunnel("8.8.8.8"), None)
    assert out.tunnels[0].local_ip_mismatch is False


def test_annotate_is_immutable() -> None:
    status = _tunnel("8.8.8.8")
    annotate_local_ip_mismatch(status, ExternalIp(ipv4="9.9.9.9"))
    assert status.tunnels[0].local_ip_mismatch is False  # original untouched


# --- route: GET /instances/{id}/external-ip ---------------------------------


async def _noop(*a: object, **k: object) -> None:
    return None


class _Sess:
    async def commit(self) -> None:
        return None


def _app(monkeypatch, inst: object) -> object:
    monkeypatch.setattr(main_mod, "start_scheduler", lambda: None)
    monkeypatch.setattr(main_mod, "ensure_admin", _noop)
    monkeypatch.setattr(main_mod, "ensure_superadmin", _noop)

    async def _get_instance(session: object, iid: int, principal: object = None) -> object:
        return inst

    monkeypatch.setattr(metrics_mod, "get_instance", _get_instance)
    app = main_mod.create_app()
    app.dependency_overrides[current_user] = lambda: SimpleNamespace(
        id=1, role="admin", is_admin=True, is_superadmin=False, group_id_set=frozenset({1})
    )
    app.dependency_overrides[get_session] = lambda: _Sess()
    return app


def _wire_hub(monkeypatch, *, ext, source_ip, ifaces, connected=True) -> None:
    monkeypatch.setattr(metrics_mod.hub, "get_last_external_ip", lambda iid: ext)
    monkeypatch.setattr(metrics_mod.hub, "get_source_ip", lambda iid: source_ip)
    monkeypatch.setattr(
        metrics_mod.hub,
        "get_last_status",
        lambda iid: SystemStatus(interfaces=[InterfaceStats(address=a) for a in ifaces]),
    )
    monkeypatch.setattr(metrics_mod.hub, "is_connected", lambda iid: connected)


def test_external_ip_route_flags_behind_nat(monkeypatch) -> None:
    # Public IPv4 differs from the box's (private) interface address → behind NAT.
    _wire_hub(
        monkeypatch,
        ext=ExternalIp(ipv4="203.0.113.7", ipv6="2001:db8::1", checked_at="t"),
        source_ip="203.0.113.7",
        ifaces=["192.168.1.2"],
    )
    app = _app(monkeypatch, SimpleNamespace(id=1, deleted_at=None, group_id=1))
    with TestClient(app) as c:
        r = c.get("/api/instances/1/external-ip")
    assert r.status_code == 200
    body = r.json()
    assert body["ipv4"] == "203.0.113.7"
    assert body["ipv6"] == "2001:db8::1"
    assert body["source_ip"] == "203.0.113.7"
    assert body["behind_nat"] is True
    assert body["connected"] is True


def test_external_ip_route_direct_when_public_on_interface(monkeypatch) -> None:
    # The box owns the public IPv4 on an interface → not behind NAT.
    _wire_hub(
        monkeypatch,
        ext=ExternalIp(ipv4="203.0.113.7"),
        source_ip="203.0.113.7",
        ifaces=["203.0.113.7"],
    )
    app = _app(monkeypatch, SimpleNamespace(id=1, deleted_at=None, group_id=1))
    with TestClient(app) as c:
        r = c.get("/api/instances/1/external-ip")
    assert r.status_code == 200
    assert r.json()["behind_nat"] is False


def test_external_ip_route_out_of_scope_404(monkeypatch) -> None:
    # Out-of-scope / missing instance → 404, never a 403 existence oracle.
    _wire_hub(monkeypatch, ext=None, source_ip=None, ifaces=[])
    app = _app(monkeypatch, None)
    with TestClient(app) as c:
        r = c.get("/api/instances/1/external-ip")
    assert r.status_code == 404
