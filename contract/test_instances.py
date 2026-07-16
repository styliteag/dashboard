"""Instances contract: flat list (no envelope), 404-not-403, literal-before-param."""


def test_list_requires_auth(anon):
    assert anon.get("/api/instances").status_code == 401


def test_list_is_flat_array(admin):
    resp = admin.get("/api/instances")

    assert resp.status_code == 200
    body = resp.json()
    # Deliberately NO {success, data, ...} envelope and no pagination wrapper
    # here — the frontend maps over a plain array (repo rule).
    assert isinstance(body, list)
    for item in body:
        for key in ("id", "name"):
            assert key in item, f"missing instance key: {key}"
        # Secrets never appear — booleans only (security invariant 3).
        assert "api_secret" not in item
        assert "ssh_key" not in item


def test_defaults_route_wins_over_id_param(admin):
    # Regression guard: the literal /instances/defaults must be matched BEFORE
    # /instances/{instance_id} (route-ordering rule in CLAUDE.md) — a backend
    # that parses "defaults" as an id answers 404/422 here.
    resp = admin.get("/api/instances/defaults")

    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)


def test_missing_instance_is_404(admin):
    # Missing and out-of-scope must be indistinguishable (404, never 403 —
    # security invariant 1). Admin-visible stack only proves the missing arm;
    # the out-of-scope arm needs a zero-group user (M1 backlog: scoped-user
    # fixtures via the users/groups API).
    resp = admin.get("/api/instances/999999999")

    assert resp.status_code == 404
    assert "detail" in resp.json()
