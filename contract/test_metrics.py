"""Metrics read contract: on-the-fly bucketing of the raw table (no rollups)."""

import re

import pytest

# Bucket timestamps come from FROM_UNIXTIME(... DIV n * n) and serialize
# NAIVE (no +00:00) — semantically UTC. The frontend parses exactly this;
# a migrated backend must reproduce it byte for byte.
NAIVE_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")


def _first_instance_id(admin) -> int:
    instances = admin.get("/api/instances").json()
    if not instances:
        pytest.skip("dev stack has no instances")
    return instances[0]["id"]


def test_metrics_require_auth(anon):
    assert anon.get("/api/instances/1/metrics").status_code == 401


def test_metrics_shape(admin):
    instance_id = _first_instance_id(admin)

    resp = admin.get(f"/api/instances/{instance_id}/metrics", params={"minutes": 60})

    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"metric", "instance_id", "points"}
    assert body["instance_id"] == instance_id
    assert isinstance(body["points"], list)
    for point in body["points"]:
        assert set(point) == {"ts", "value"}
        assert NAIVE_TS.match(point["ts"]), f"bucket ts drifted: {point['ts']}"
        assert point["value"] is None or isinstance(point["value"], (int, float))


def test_metrics_are_scoped(scoped_user, admin):
    instance_id = _first_instance_id(admin)

    resp = scoped_user.get(f"/api/instances/{instance_id}/metrics")

    assert resp.status_code == 404
