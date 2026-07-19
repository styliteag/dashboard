"""Groups contract: superadmin-only rights management, full CRUD lifecycle."""

import uuid


def test_groups_require_auth(anon):
    assert anon.get("/api/groups").status_code == 401


def test_groups_are_superadmin_only_even_for_admin(admin):
    # Group management is rights management — an instance admin has no
    # business here (superadmin/admin separation, invariant 1).
    assert admin.get("/api/groups").status_code == 403


def test_group_crud_lifecycle(superadmin):
    name = f"contract-group-{uuid.uuid4().hex[:8]}"

    created = superadmin.post("/api/groups", json={"name": name})
    assert created.status_code in (200, 201), f"group create failed: {created.text}"
    group = created.json()
    assert group["name"] == name
    group_id = group["id"]

    try:
        listed = superadmin.get("/api/groups")
        assert listed.status_code == 200
        assert any(g["id"] == group_id for g in listed.json())
    finally:
        deleted = superadmin.delete(f"/api/groups/{group_id}")
        assert deleted.status_code in (200, 204), f"group delete failed: {deleted.text}"

    listed_after = superadmin.get("/api/groups")
    assert all(g["id"] != group_id for g in listed_after.json())
