"""Machine-export contract: Checkmk JSON + Prometheus text.

These are the surfaces scraped on a cadence (gather_many_cached behind them,
20 s TTL) — the exact shapes are parsed by the Checkmk special agent and by
Prometheus, so they are frozen here. Labels: instance_id/instance_name, NEVER
`instance` (reserved by Prometheus itself — rule 20 in CLAUDE.md).
"""

import re
import uuid

import httpx
import pytest
from conftest import BASE_URL

VALID_STATES = {0, 1, 2, 3}


def test_checkmk_export_shape(admin):
    resp = admin.get("/api/export/checkmk")

    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 1
    assert isinstance(body["instances"], list)
    for inst in body["instances"]:
        for key in ("instance_id", "name", "host", "device_type", "checks"):
            assert key in inst, f"missing instance key: {key}"
        for check in inst["checks"]:
            for key in ("key", "state", "summary", "metrics"):
                assert key in check, f"missing check key: {key}"
            assert check["state"] in VALID_STATES
            for metric in check["metrics"]:
                assert {"name", "value", "warn", "crit", "unit"} <= set(metric)


def test_prometheus_export_labels(admin):
    resp = admin.get("/api/export/prometheus")

    assert resp.status_code == 200
    text = resp.text
    assert "orbit_instance_info" in text

    families_with_help = set(re.findall(r"^# HELP (\S+)", text, re.MULTILINE))
    sample_families = set(re.findall(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\{", text, re.MULTILINE))
    # Every emitted family must be registered in _HELP (rule 20: an
    # unregistered family is silently never emitted — and vice versa a sample
    # without HELP breaks strict parsers).
    assert sample_families <= families_with_help, sample_families - families_with_help

    # instance_id/instance_name label the series; a literal `instance` label
    # would collide with Prometheus' reserved target label.
    assert 'instance_id="' in text
    assert 'instance_name="' in text
    assert re.search(r'[{,]instance="', text) is None


def test_exports_honor_key_binding(admin, superadmin):
    instances = admin.get("/api/instances").json()
    if not instances:
        pytest.skip("dev stack has no instances")
    bound_group = instances[0]["group_id"]
    expected_ids = {i["instance_id"] for i in _checkmk_for_admin(admin)["instances"]}
    group_ids = {i["id"] for i in instances if i["group_id"] == bound_group}

    created = admin.post(
        "/api/apikeys",
        json={"name": f"contract-export-{uuid.uuid4().hex[:8]}", "group_ids": [bound_group]},
    )
    assert created.status_code == 200
    key = created.json()

    try:
        headers = {"Authorization": f"Bearer {key['key']}"}
        with httpx.Client(base_url=BASE_URL, timeout=10, headers=headers) as key_client:
            body = key_client.get("/api/export/checkmk").json()
            exported_ids = {i["instance_id"] for i in body["instances"]}
            # The bound key exports exactly its group's instances — nothing else
            # (hub state is unscoped in-memory data; every export must filter,
            # security invariant 5).
            assert exported_ids == group_ids
            assert exported_ids <= expected_ids
    finally:
        assert superadmin.delete(f"/api/apikeys/{key['id']}").status_code == 200


def _checkmk_for_admin(admin) -> dict:
    resp = admin.get("/api/export/checkmk")
    assert resp.status_code == 200
    return resp.json()
