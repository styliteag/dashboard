"""Group-scoping contract — security invariant 1 (change-frozen semantics).

Pinned here, black-box:

- A user with ZERO groups sees NOTHING. (Inverted for ApiKeys, where zero
  bindings mean GLOBAL — the key arm still needs its own fixture, M1 backlog.)
- Out-of-scope answers 404, never 403, and the body is indistinguishable from
  a missing id — no existence oracle.

The throwaway user is created by the superadmin, enrolls TOTP with the
stdlib helper from conftest (non-bootstrap logins never mint a session on
password alone), and is deleted again in the fixture teardown.
"""

import pytest

# The scoped_user fixture (throwaway zero-group view_only user with a real
# TOTP enrollment) lives in conftest.py — other route families reuse it.


def test_zero_group_user_sees_nothing(scoped_user):
    resp = scoped_user.get("/api/instances")

    assert resp.status_code == 200
    assert resp.json() == []


def test_out_of_scope_is_404_and_identical_to_missing(scoped_user, admin):
    instances = admin.get("/api/instances").json()
    if not instances:
        pytest.skip("dev stack has no instances to exercise the out-of-scope arm")
    real_id = instances[0]["id"]

    out_of_scope = scoped_user.get(f"/api/instances/{real_id}")
    missing = scoped_user.get("/api/instances/999999999")

    assert out_of_scope.status_code == 404
    assert missing.status_code == 404
    # Same body for "exists but not yours" and "does not exist" — the
    # response must not reveal which one it was.
    assert out_of_scope.json() == missing.json()


def test_superadmin_has_zero_instance_access(superadmin):
    # Superadmin = rights management only; NO instance bypass (invariant 1).
    resp = superadmin.get("/api/instances")

    assert resp.status_code == 200
    assert resp.json() == []
