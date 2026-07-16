"""GET /api/health — liveness contract.

Anonymous, exact key set (the frontend and monitoring probes parse this),
never leaks DB/driver detail.
"""


def test_health_ok_shape(anon):
    resp = anon.get("/api/health")

    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"status", "db", "version", "db_revision"}
    assert body["status"] == "ok"
    assert body["db"] == "ok"
    assert isinstance(body["version"], str) and body["version"]
    # db_revision is the alembic head — a zero-padded string like "041"
    assert isinstance(body["db_revision"], str) and body["db_revision"]
