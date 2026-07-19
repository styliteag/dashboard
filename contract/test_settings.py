"""Settings contract: admin-only registry, secret values never leave the API."""

SETTING_KEYS = {
    "key",
    "label",
    "group",
    "type",
    "help",
    "value",
    "default",
    "source",
    "restart_required",
    "is_secret",
    "options",
}


def test_settings_require_auth(anon):
    assert anon.get("/api/settings").status_code == 401


def test_settings_are_admin_only(scoped_user):
    # view_only is a valid session but not admin — config surfaces sit behind
    # require_admin on the dependency ladder.
    assert scoped_user.get("/api/settings").status_code == 403


def test_settings_shape_and_secret_masking(admin):
    resp = admin.get("/api/settings")

    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list) and body
    for setting in body:
        assert set(setting) >= SETTING_KEYS, f"missing keys on {setting.get('key')}"
        if setting["is_secret"]:
            # Secret values NEVER leave the API in plaintext (invariant 3):
            # empty when unset, bullet-masked when set.
            value = setting["value"]
            assert value == "" or set(value) == {"•"}, (
                f"secret setting {setting['key']} leaked its value"
            )


def test_settings_write_is_admin_gated(scoped_user):
    # Bulk PUT on the collection; per-key DELETE resets an override.
    resp = scoped_user.put("/api/settings", json={"poll_interval_seconds": "30"})
    assert resp.status_code == 403

    reset = scoped_user.delete("/api/settings/poll_interval_seconds")
    assert reset.status_code == 403
