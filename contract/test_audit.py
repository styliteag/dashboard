"""Audit log contract: paginated envelope (the repo's pagination convention)."""

ITEM_KEYS = {
    "id",
    "ts",
    "user_id",
    "username",
    "action",
    "target_type",
    "target_id",
    "request_id",
    "result",
    "detail",
    "source_ip",
    "source_country",
    "source_country_name",
}


def test_audit_requires_auth(anon):
    assert anon.get("/api/audit").status_code == 401


def test_audit_is_admin_only(scoped_user):
    assert scoped_user.get("/api/audit").status_code == 403


def test_audit_envelope_and_pagination(admin):
    resp = admin.get("/api/audit", params={"page_size": 1})

    assert resp.status_code == 200
    body = resp.json()
    # items/total/page/page_size — THE pagination envelope of this API
    # (deliberately not {success, data, meta}).
    assert set(body) == {"items", "total", "page", "page_size"}
    assert body["page"] == 1
    assert body["page_size"] == 1
    assert len(body["items"]) <= 1
    assert isinstance(body["total"], int)
    for item in body["items"]:
        assert set(item) >= ITEM_KEYS
        # ts serializes timezone-aware UTC (+00:00) — MariaDB reads back naive,
        # the API must re-tag before serializing (UtcDateTime contract).
        assert item["ts"].endswith("+00:00")
