"""Dependency-ladder contract: a valid view_only session gets 403 on writes.

Distinguishes the two failure modes pinned across the suite:
- no/invalid session -> 401 (tested per family)
- valid session, insufficient role -> 403, and the mutation never happens
"""


def test_view_only_cannot_create_instances(scoped_user):
    resp = scoped_user.post("/api/instances", json={"name": "contract-nope"})
    assert resp.status_code == 403


def test_view_only_cannot_create_users(scoped_user):
    resp = scoped_user.post(
        "/api/users",
        json={"username": "contract-nope", "password": "x" * 12, "role": "view_only"},
    )
    # users API is superadmin-gated — a plain session bounces regardless of payload
    assert resp.status_code == 403


def test_admin_is_not_superadmin(admin):
    # Instance admin != rights admin: user creation stays superadmin-only.
    resp = admin.post(
        "/api/users",
        json={"username": "contract-nope", "password": "x" * 12, "role": "view_only"},
    )
    assert resp.status_code == 403
