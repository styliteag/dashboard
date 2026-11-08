defmodule Orbit.GUI.BoundCookieTest do
  @moduledoc """
  The `orbit_gui` cookie (and the handoff token it is minted from) is bound
  to the user who opened the GUI and to his password_version: a password
  change, a disabled account or a lost group membership ends GUI access on
  the next proxied request instead of when the cookie expires.
  """
  use Orbit.DataCase, async: false

  alias Orbit.GUI
  alias Orbit.GUI.Auth

  defp unique, do: System.unique_integer([:positive])

  defp group! do
    Repo.insert!(%Orbit.Accounts.Group{name: "gui-#{unique()}"}).id
  end

  defp instance!(group_id) do
    name = "gui-inst-#{unique()}"

    Repo.query!(
      "INSERT INTO instances (name, base_url, api_key_enc, api_secret_enc, slug, " <>
        "group_id, transport, device_type, created_at, updated_at) " <>
        "VALUES (?, '', '', '', ?, ?, 'push', 'opnsense', NOW(), NOW())",
      [name, name, group_id]
    )

    [[id]] = Repo.query!("SELECT id FROM instances WHERE name = ?", [name]).rows
    id
  end

  defp user!(group_id) do
    name = "gui-user-#{unique()}"
    Repo.query!("INSERT INTO users (username, password_hash) VALUES (?, 'x')", [name])
    [[id]] = Repo.query!("SELECT id FROM users WHERE username = ?", [name]).rows
    Repo.query!("INSERT INTO user_groups VALUES (?, ?)", [id, group_id])
    Orbit.Accounts.get_user(id)
  end

  setup do
    gid = group!()
    {:ok, inst: instance!(gid), user: user!(gid), other_inst: instance!(group!())}
  end

  test "bound tokens round-trip and carry the binding" do
    t = Auth.sign_bound(5, 9, 3, 60)
    assert {:ok, %{instance_id: 5, user_id: 9, password_version: 3}} = Auth.verify_bound(t)
    assert Auth.verify_bound(Auth.sign(5, 60)) == :error
    assert Auth.verify_bound(Auth.sign_bound(5, 9, 3, 60, 1_000), 2_000) == :error
  end

  test "a cookie of a valid user for an instance in his scope passes", c do
    assert GUI.authorized?(GUI.cookie_token(c.inst, c.user), c.inst)
  end

  test "another instance id does not pass", c do
    refute GUI.authorized?(GUI.cookie_token(c.inst, c.user), c.other_inst)
  end

  test "a password change (version bump) ends it", c do
    token = GUI.cookie_token(c.inst, c.user)

    Repo.query!("UPDATE users SET password_version = password_version + 1 WHERE id = ?", [
      c.user.id
    ])

    refute GUI.authorized?(token, c.inst)
  end

  test "a disabled user is refused", c do
    token = GUI.cookie_token(c.inst, c.user)
    Repo.query!("UPDATE users SET disabled = 1 WHERE id = ?", [c.user.id])
    refute GUI.authorized?(token, c.inst)
  end

  test "losing the group membership (scope change) ends it", c do
    token = GUI.cookie_token(c.inst, c.user)
    Repo.query!("DELETE FROM user_groups WHERE user_id = ?", [c.user.id])
    refute GUI.authorized?(token, c.inst)
  end

  test "an unbound (legacy) token is refused", c do
    refute GUI.authorized?(Auth.sign(c.inst, 3600), c.inst)
  end
end
