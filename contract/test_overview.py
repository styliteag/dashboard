"""Overview contract: the aggregate is scoped like everything else."""


def test_overview_requires_auth(anon):
    assert anon.get("/api/overview").status_code == 401


def test_overview_shape_and_scope(admin):
    resp = admin.get("/api/overview")

    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"total", "online", "offline", "degraded"}
    for value in body.values():
        assert isinstance(value, int)
    # The aggregate honors scope_clause: total == what the same principal
    # sees in the instances list (invariant 1 applies to aggregates too).
    instances = admin.get("/api/instances").json()
    assert body["total"] == len(instances)


def test_overview_is_empty_for_zero_group_user(scoped_user):
    resp = scoped_user.get("/api/overview")

    assert resp.status_code == 200
    assert resp.json() == {"total": 0, "online": 0, "offline": 0, "degraded": 0}
