"""Fleet-wide certificate overview aggregation (app.views.routes.certs_overview)."""

from __future__ import annotations

import asyncio

from app.views import routes as vr
from app.xsense.schemas import CertInfo


class _FakeInst:
    def __init__(self, id: int, name: str, agent_mode: bool = True, location=None):
        self.id = id
        self.name = name
        self.agent_mode = agent_mode
        self.location = location


def _run(monkeypatch, instances, certs_by_id):
    async def fake_list(_session, _user):
        return instances

    monkeypatch.setattr(vr, "list_instances", fake_list)
    monkeypatch.setattr(vr.hub, "get_last_certs", lambda iid: certs_by_id.get(iid))
    return asyncio.run(vr.certs_overview(session=None, user=None))


def test_aggregates_counts_sorts_and_skips_direct(monkeypatch) -> None:
    instances = [
        _FakeInst(1, "opn1"),
        _FakeInst(2, "direct", agent_mode=False),  # non-agent → contributes nothing
        _FakeInst(3, "opn2"),
    ]
    certs = {
        1: [
            CertInfo(
                refid="a",
                name="gui",
                is_gui=True,
                days_remaining=5,
                issuer="CN = OPNsense.internal",
            ),
            CertInfo(
                refid="b", name="le", days_remaining=15, issuer="C = US, O = Let's Encrypt, CN = R3"
            ),
        ],
        2: [CertInfo(refid="x", days_remaining=1)],  # must be skipped (direct)
        3: [
            CertInfo(
                refid="c",
                name="root-ca",
                type="ca",
                days_remaining=400,
                issuer="CN = OPNsense.internal",
            ),
            CertInfo(refid="d", name="old", days_remaining=-3, issuer="CN = whatever"),
        ],
    }
    resp = _run(monkeypatch, instances, certs)

    assert resp.total == 4  # inst 2 excluded
    assert resp.critical == 1  # 5d
    assert resp.warning == 1  # 15d
    assert resp.ok == 1  # 400d
    assert resp.expired == 1  # -3d
    assert resp.acme == 1  # the Let's Encrypt cert
    assert resp.acme_overdue == 1  # LE cert at 15d (< 21) → renewal overdue
    # soonest-expiry-first
    assert [c.days_remaining for c in resp.certs] == [-3, 5, 15, 400]


def test_acme_healthy_not_overdue(monkeypatch) -> None:
    certs = {1: [CertInfo(refid="a", days_remaining=60, issuer="O = Let's Encrypt, CN = R11")]}
    resp = _run(monkeypatch, [_FakeInst(1, "opn1")], certs)
    assert resp.acme == 1
    assert resp.acme_overdue == 0  # 60d > renew window → healthy
    assert resp.certs[0].status == "ok"


def test_self_signed_is_not_acme(monkeypatch) -> None:
    certs = {
        1: [CertInfo(refid="a", days_remaining=10, issuer="O = pfSense GUI default Self-Signed")]
    }
    resp = _run(monkeypatch, [_FakeInst(1, "pf1")], certs)
    assert resp.acme == 0 and resp.acme_overdue == 0
    assert resp.warning == 1


def test_empty_fleet(monkeypatch) -> None:
    resp = _run(monkeypatch, [_FakeInst(1, "opn1")], {1: None})
    assert resp.total == 0 and resp.certs == []
