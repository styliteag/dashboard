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

import uuid

import httpx
import pytest
from conftest import BASE_URL, login, totp_code


@pytest.fixture()
def scoped_user(superadmin):
    username = f"contract-scoped-{uuid.uuid4().hex[:8]}"
    password = "contract-throwaway-pw"

    created = superadmin.post(
        "/api/users",
        json={"username": username, "password": password, "role": "view_only", "group_ids": []},
    )
    assert created.status_code == 201, f"user create failed: {created.status_code} {created.text}"
    user_id = created.json()["id"]

    client = httpx.Client(base_url=BASE_URL, timeout=10)
    try:
        challenge = login(client, username, password)
        assert challenge.status_code == 200
        assert challenge.json()["stage"] == "enroll"

        setup = client.post("/api/auth/mfa/setup/totp")
        assert setup.status_code == 200, f"totp setup failed: {setup.status_code} {setup.text}"
        secret = setup.json()["secret"]

        confirm = client.post("/api/auth/mfa/confirm/totp", json={"code": totp_code(secret)})
        assert confirm.status_code == 200, f"totp confirm failed: {confirm.status_code}"

        yield client
    finally:
        client.close()
        deleted = superadmin.delete(f"/api/users/{user_id}")
        assert deleted.status_code == 204, f"cleanup failed for user {user_id}"


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
