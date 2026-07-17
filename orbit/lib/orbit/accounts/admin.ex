defmodule Orbit.Accounts.Admin do
  @moduledoc """
  Superadmin rights management — port of users/routes.py mutations. Every
  guard is python-parity and security-load-bearing:

  - You can never demote/delete YOURSELF, nor the LAST admin or LAST
    superadmin (lockout prevention).
  - A password reset bumps password_version, killing the target's live
    sessions (the DR-AL5 cheap-kill mechanism).
  - reset-2fa wipes TOTP + all passkeys + bumps password_version — the
    lost-authenticator recovery.
  - Bootstrap retirement (auth/bootstrap.py port): once a REAL admin /
    superadmin exists, the password-only seed account auto-disables —
    unless the operator forces it on (DASH_*_DISABLED=0 → mode enabled).
    This is a PORT of the change-frozen python semantics, not an edit of
    them; behaviour verified against the python source line by line.

  Group membership is a replace-set over user_groups (raw SQL — the schema
  stays read-only-shaped); unknown ids refuse the whole write.
  """

  import Ecto.Query

  alias Orbit.Accounts.User
  alias Orbit.Auth.Password
  alias Orbit.Repo

  @role_admin "admin"
  @roles ~w(admin user view_only)

  def roles, do: @roles

  # -- create ----------------------------------------------------------------

  def create_user(params) do
    username = String.trim(params["username"] || "")
    password = params["password"] || ""
    role = if params["role"] in @roles, do: params["role"], else: "user"
    is_superadmin = params["is_superadmin"] in [true, "true", "on"]

    cond do
      username == "" ->
        {:error, :username_required}

      String.length(password) < 8 ->
        {:error, :password_too_short}

      true ->
        with {:ok, group_ids} <- validate_group_ids(params["group_ids"] || []) do
          insert_user(username, password, role, is_superadmin, group_ids)
        end
    end
  end

  defp insert_user(username, password, role, is_superadmin, group_ids) do
    %User{}
    |> Ecto.Changeset.change(%{
      username: username,
      password_hash: Password.hash(password),
      password_version: 1,
      role: role,
      is_superadmin: is_superadmin,
      totp_enabled: false,
      is_bootstrap: false,
      disabled: false,
      created_at: DateTime.utc_now()
    })
    |> Repo.insert()
    |> case do
      {:ok, user} ->
        replace_groups(user.id, group_ids)
        if role == @role_admin, do: retire_bootstrap(false)
        if is_superadmin, do: retire_bootstrap(true)
        {:ok, Orbit.Accounts.get_user(user.id)}

      {:error, _} ->
        {:error, :conflict}
    end
  rescue
    Ecto.ConstraintError -> {:error, :conflict}
  end

  # -- update ----------------------------------------------------------------

  @doc "Role/superadmin/groups/password update with self- and last-guards."
  def update_user(%User{} = target, params, %User{} = actor) do
    role = params["role"]
    set_superadmin = parse_bool(params["is_superadmin"])

    cond do
      role != nil and role not in @roles ->
        {:error, :bad_role}

      role != nil and role != @role_admin and target.role == @role_admin and
          target.id == actor.id ->
        {:error, :cannot_demote_self}

      role != nil and role != @role_admin and target.role == @role_admin and
          admin_count() <= 1 ->
        {:error, :last_admin}

      set_superadmin == false and target.is_superadmin and target.id == actor.id ->
        {:error, :cannot_revoke_own_superadmin}

      set_superadmin == false and target.is_superadmin and superadmin_count() <= 1 ->
        {:error, :last_superadmin}

      true ->
        apply_update(target, params, role, set_superadmin)
    end
  end

  defp apply_update(target, params, role, set_superadmin) do
    with {:ok, group_ids} <- maybe_group_ids(params) do
      changes =
        %{}
        |> maybe_put(:role, role)
        |> maybe_put(:is_superadmin, set_superadmin)
        |> maybe_password(params["new_password"], target)

      {:ok, _} = target |> Ecto.Changeset.change(changes) |> Repo.update()
      if group_ids != nil, do: replace_groups(target.id, group_ids)
      if role == @role_admin and not target.is_bootstrap, do: retire_bootstrap(false)
      if set_superadmin == true and not target.is_bootstrap, do: retire_bootstrap(true)
      {:ok, Orbit.Accounts.get_user(target.id)}
    end
  end

  defp maybe_password(changes, password, target) do
    if password not in [nil, ""] do
      changes
      |> Map.put(:password_hash, Password.hash(password))
      # Kills the target's live sessions (password_version check per request).
      |> Map.put(:password_version, target.password_version + 1)
    else
      changes
    end
  end

  # -- delete / reset-2fa ----------------------------------------------------

  def delete_user(%User{} = target, %User{} = actor) do
    cond do
      target.id == actor.id -> {:error, :cannot_delete_self}
      target.role == @role_admin and admin_count() <= 1 -> {:error, :last_admin}
      target.is_superadmin and superadmin_count() <= 1 -> {:error, :last_superadmin}
      true -> Repo.delete(target)
    end
  end

  @doc "Wipe TOTP + passkeys, bump password_version — forces 2FA re-enrollment."
  def reset_2fa(%User{} = target) do
    {:ok, updated} =
      target
      |> Ecto.Changeset.change(%{
        totp_enabled: false,
        totp_secret_enc: nil,
        password_version: target.password_version + 1
      })
      |> Repo.update()

    Repo.query!("DELETE FROM webauthn_credentials WHERE user_id = ?", [target.id])
    {:ok, updated}
  end

  # -- groups (groups/routes.py port) ----------------------------------------

  def create_group(name) do
    name = String.trim(to_string(name || ""))

    if name == "" do
      {:error, :name_required}
    else
      %Orbit.Accounts.Group{}
      |> Ecto.Changeset.change(%{name: name, created_at: DateTime.utc_now()})
      |> Repo.insert()
      |> case do
        {:ok, group} -> {:ok, group}
        {:error, _} -> {:error, :conflict}
      end
    end
  rescue
    Ecto.ConstraintError -> {:error, :conflict}
  end

  def rename_group(%Orbit.Accounts.Group{} = group, name) do
    name = String.trim(to_string(name || ""))

    if name == "" do
      {:error, :name_required}
    else
      group
      |> Ecto.Changeset.change(%{name: name})
      |> Repo.update()
      |> case do
        {:ok, g} -> {:ok, g}
        {:error, _} -> {:error, :conflict}
      end
    end
  rescue
    Ecto.ConstraintError -> {:error, :conflict}
  end

  @doc """
  Delete a group — two 409 guards (groups/routes.py parity, both
  security-load-bearing): instances (INCLUDING soft-deleted, they still
  hold the FK) block the delete; and an active api key bound to ONLY this
  group blocks it too — apikey_groups CASCADEs, and a key whose last
  binding disappears becomes GLOBAL (empty set = unscoped, invariant 1).
  """
  def delete_group(%Orbit.Accounts.Group{} = group) do
    instance_count =
      Repo.one(
        from(i in Orbit.Instances.Instance, where: i.group_id == ^group.id, select: count())
      )

    cond do
      instance_count > 0 ->
        {:error, :has_instances}

      sole_binding_key_name(group.id) != nil ->
        {:error, {:sole_apikey_binding, sole_binding_key_name(group.id)}}

      true ->
        Repo.delete(group)
    end
  end

  # Name of an ACTIVE api key whose only group binding is this group (or nil).
  defp sole_binding_key_name(group_id) do
    %{rows: rows} =
      Repo.query!(
        "SELECT k.id, k.name FROM api_keys k " <>
          "JOIN apikey_groups ag ON ag.apikey_id = k.id " <>
          "WHERE ag.group_id = ? AND k.revoked_at IS NULL",
        [group_id]
      )

    Enum.find_value(rows, fn [key_id, name] ->
      %{rows: [[n]]} =
        Repo.query!("SELECT COUNT(*) FROM apikey_groups WHERE apikey_id = ?", [key_id])

      if n == 1, do: name
    end)
  end

  # -- helpers ---------------------------------------------------------------

  defp admin_count do
    Repo.one(from(u in User, where: u.role == @role_admin, select: count()))
  end

  defp superadmin_count do
    Repo.one(from(u in User, where: u.is_superadmin == true, select: count()))
  end

  defp maybe_group_ids(params) do
    case params["group_ids"] do
      nil -> {:ok, nil}
      ids -> validate_group_ids(ids)
    end
  end

  defp validate_group_ids(ids) when is_list(ids) do
    unique = ids |> Enum.map(&parse_int/1) |> Enum.uniq()

    if Enum.any?(unique, &is_nil/1) do
      {:error, :unknown_groups}
    else
      found =
        Repo.all(from(g in Orbit.Accounts.Group, where: g.id in ^unique, select: g.id))

      if length(found) == length(unique), do: {:ok, unique}, else: {:error, :unknown_groups}
    end
  end

  defp validate_group_ids(_), do: {:error, :unknown_groups}

  # Replace-set over the join table (schema stays read-only-shaped).
  defp replace_groups(user_id, group_ids) do
    Repo.query!("DELETE FROM user_groups WHERE user_id = ?", [user_id])

    for gid <- group_ids do
      Repo.query!("INSERT IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)", [
        user_id,
        gid
      ])
    end

    :ok
  end

  # Disable the password-only seed account once a real one exists — skipped
  # when the operator forces the seed on (DASH_*_DISABLED=0 → "enabled").
  defp retire_bootstrap(superadmin?) do
    env = if superadmin?, do: :superadmin_disabled_raw, else: :admin_disabled_raw
    raw = Application.get_env(:orbit, env, "auto") |> to_string() |> String.downcase()

    unless raw in ~w(0 false no off) do
      from(u in User,
        where: u.is_bootstrap == true and u.is_superadmin == ^superadmin? and u.disabled == false
      )
      |> Repo.update_all(set: [disabled: true])
    end

    :ok
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp parse_bool(nil), do: nil
  defp parse_bool(v), do: v in [true, "true", "on"]

  defp parse_int(v) do
    case Integer.parse(to_string(v)) do
      {n, ""} -> n
      _ -> nil
    end
  end
end
