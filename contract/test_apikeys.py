"""ApiKey contract — the OTHER arm of the empty-set semantics.

Security invariant 1: a User with zero groups sees NOTHING (test_scoping.py),
but an ApiKey with zero bindings is GLOBAL. Both are change-frozen. Keys are
``orbit_…`` bearer tokens, read-only by construction, and only routes built on
``read_principal`` accept them (checks, exports) — session-only routes answer
401 even to a valid key.
"""

import uuid

import httpx
import pytest
from conftest import BASE_URL


def _bearer(token: str) -> httpx.Client:
    return httpx.Client(base_url=BASE_URL, timeout=10, headers={"Authorization": f"Bearer {token}"})


@pytest.fixture()
def global_key(superadmin):
    """Zero-binding key = GLOBAL. Only the superadmin may mint one."""
    created = superadmin.post(
        "/api/apikeys",
        json={"name": f"contract-global-{uuid.uuid4().hex[:8]}", "group_ids": []},
    )
    assert created.status_code == 200, f"global key create failed: {created.text}"
    body = created.json()
    assert body["key"].startswith("orbit_")
    yield body["key"]
    assert superadmin.delete(f"/api/apikeys/{body['id']}").status_code == 200


def _visible_instances(admin) -> list[dict]:
    resp = admin.get("/api/instances")
    assert resp.status_code == 200
    return resp.json()


def test_admin_cannot_mint_global_key(admin):
    resp = admin.post(
        "/api/apikeys",
        json={"name": f"contract-illegal-{uuid.uuid4().hex[:8]}", "group_ids": []},
    )
    # A group-scoped admin must bind to his groups; a global key would bypass
    # his instance scoping.
    assert resp.status_code == 403


def test_key_auth_needs_no_session_and_zero_bindings_are_global(global_key, admin):
    instances = _visible_instances(admin)
    if not instances:
        pytest.skip("dev stack has no instances")

    with _bearer(global_key) as key_client:
        resp = key_client.get(f"/api/instances/{instances[0]['id']}/checks")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


def test_bound_key_is_scoped_404_not_403(admin, superadmin):
    instances = _visible_instances(admin)
    if not instances:
        pytest.skip("dev stack has no instances")
    in_scope = instances[0]
    bound_group = in_scope["group_id"]

    created = admin.post(
        "/api/apikeys",
        json={"name": f"contract-bound-{uuid.uuid4().hex[:8]}", "group_ids": [bound_group]},
    )
    assert created.status_code == 200, f"bound key create failed: {created.text}"
    key = created.json()

    try:
        with _bearer(key["key"]) as key_client:
            ok = key_client.get(f"/api/instances/{in_scope['id']}/checks")
            assert ok.status_code == 200

            out_of_scope = next((i for i in instances if i["group_id"] != bound_group), None)
            if out_of_scope is not None:
                denied = key_client.get(f"/api/instances/{out_of_scope['id']}/checks")
                missing = key_client.get("/api/instances/999999999/checks")
                # Out-of-scope == missing: 404 with an identical body, never 403.
                assert denied.status_code == 404
                assert missing.status_code == 404
                assert denied.json() == missing.json()
    finally:
        assert superadmin.delete(f"/api/apikeys/{key['id']}").status_code == 200


def test_key_is_read_only_and_useless_on_session_routes(global_key):
    with _bearer(global_key) as key_client:
        # Session-only surface: a valid key is NOT a session (401, not 403 —
        # the instances CRUD never accepts keys at all).
        assert key_client.get("/api/instances").status_code == 401
        # Mutation attempt: read-only by construction.
        resp = key_client.post("/api/instances", json={"name": "nope"})
        assert resp.status_code in (401, 403)
        assert resp.status_code != 201


def test_revoked_key_is_dead(superadmin, admin):
    instances = _visible_instances(admin)
    if not instances:
        pytest.skip("dev stack has no instances")

    created = superadmin.post(
        "/api/apikeys",
        json={"name": f"contract-revoked-{uuid.uuid4().hex[:8]}", "group_ids": []},
    )
    assert created.status_code == 200
    key = created.json()
    assert superadmin.delete(f"/api/apikeys/{key['id']}").status_code == 200

    with _bearer(key["key"]) as key_client:
        resp = key_client.get(f"/api/instances/{instances[0]['id']}/checks")
        assert resp.status_code == 401
