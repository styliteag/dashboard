defmodule Orbit.Auth.Bootstrap do
  @moduledoc """
  Bootstrap-seed lifecycle (admin + superadmin) — port of the python
  `auth/bootstrap.py`, whose creation half was missing after the orbit cutover.

  Two seed accounts exist, each a temporary break-glass that logs in with a
  password only (**no 2FA**, see `Orbit.Accounts` login path) and is retired
  once a real counterpart exists:

  - `admin` (from `DASH_ADMIN_PASSWORD`) — role `admin`, full dashboard.
  - `superadmin` (from `DASH_SUPERADMIN_PASSWORD`) — rights management only
    (`is_superadmin=true`, role `view_only`, no group memberships → sees no
    instances at all).

  Their enabled/disabled state is *derived* on every startup:

  - **first start** (no users) → create them, enabled, password-only.
  - **another (non-bootstrap) admin/superadmin exists** → auto-disable the seed.
  - **no other enabled admin/superadmin left** → re-enable the seed and reset
    its password from the env (break-glass back in), unless explicitly retired
    with `DASH_ADMIN_DISABLED=1` / `DASH_SUPERADMIN_DISABLED=1`.

  `…_DISABLED=1` forces a seed off regardless. `Orbit.Accounts.Admin` retires a
  seed the moment a non-bootstrap counterpart is created or promoted, so a
  restart is not required. The two seed rows are told apart by their
  `is_superadmin` flag — every bootstrap lookup MUST filter on it.

  CHANGE-FROZEN semantics: this is a port, not a redesign. Behaviour was read
  off the python source (`git show c48d26e^:backend/src/app/auth/bootstrap.py`)
  line by line. Without it a greenfield deployment creates no account at all
  and nobody can log in.
  """

  import Ecto.Query
  require Logger

  alias Orbit.Accounts.Group
  alias Orbit.Accounts.User
  alias Orbit.Auth.Password
  alias Orbit.Repo

  @role_admin "admin"
  @role_view_only "view_only"

  @doc false
  def child_spec(_opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, []}, type: :worker, restart: :transient}
  end

  @doc "Run both seeds at boot, then bow out (mirrors Orbit.Repo.Migrator)."
  def start_link do
    run()
    :ignore
  end

  @doc "Seed the default group, then derive both seed accounts. Idempotent."
  def run do
    ensure_default_group()
    ensure_admin()
    ensure_superadmin()
    :ok
  end

  # -- default group ---------------------------------------------------------

  @doc """
  Seed group 1 "default" on an empty groups table.

  Alembic 028 did this as a DATA migration:

      INSERT INTO groups (id, name) VALUES (1, 'default')
      INSERT INTO user_groups (user_id, group_id) SELECT id, 1 FROM users

  The orbit baseline captures the SCHEMA only, so a greenfield database has no
  group at all. That is a dead end, not a cosmetic gap: instances carry a NOT
  NULL group_id, `Orbit.Instances.resolve_create_group/2` answers
  `:group_required` when the creator has no memberships, and `Orbit.Auth.Scope`
  gives a user with zero groups `WHERE false` — no role escapes it, by design.
  So without this the first admin can neither see nor create anything.

  Only fires when the table is empty; an existing deployment is untouched.
  """
  def ensure_default_group do
    if Repo.aggregate(Group, :count) == 0 do
      Repo.insert!(%Group{id: 1, name: "default", created_at: now()})
      Logger.info("group_bootstrap.created id=1 name=default")
    end

    :ok
  end

  # The seed admin joins "default" so it sees the fleet — 028's own rule ("every
  # existing user keeps seeing everything: member of default"). The seed
  # SUPERADMIN deliberately gets NO membership: it manages rights, not
  # instances, and must see no instance at all.
  defp join_default_group(user_id) do
    case Repo.one(from(g in Group, where: g.name == "default", select: g.id)) do
      nil ->
        :ok

      group_id ->
        Repo.insert_all("user_groups", [%{user_id: user_id, group_id: group_id}],
          on_conflict: :nothing
        )

        :ok
    end
  end

  # -- admin -----------------------------------------------------------------

  def ensure_admin do
    case seed_row(false) do
      nil ->
        maybe_create_admin()

      boot ->
        apply_seed_state(boot,
          mode: admin_mode(),
          supplanted: other_enabled_admins() > 0,
          env_password: admin_password(),
          event: "admin_bootstrap"
        )
    end
  end

  defp maybe_create_admin do
    password = admin_password()
    mode = admin_mode()

    cond do
      password in [nil, ""] ->
        Logger.warning("admin_bootstrap.skip reason=DASH_ADMIN_PASSWORD not set")

      not (first_start?() or lockout?(enabled_admins(), mode)) ->
        Logger.info("admin_bootstrap.skip reason=admin already present")

      true ->
        disabled = mode == "disabled"

        {:ok, admin} =
          insert_seed(%{
            username: "admin",
            password_hash: Password.hash(password),
            role: @role_admin,
            is_superadmin: false,
            disabled: disabled
          })

        join_default_group(admin.id)
        Logger.info("admin_bootstrap.created username=admin disabled=#{disabled}")
    end

    :ok
  end

  # -- superadmin ------------------------------------------------------------

  def ensure_superadmin do
    case seed_row(true) do
      nil ->
        maybe_create_superadmin()

      boot ->
        apply_seed_state(boot,
          mode: superadmin_mode(),
          supplanted: other_enabled_superadmins() > 0,
          env_password: superadmin_password(),
          event: "superadmin_bootstrap"
        )
    end
  end

  defp maybe_create_superadmin do
    password = superadmin_password()
    mode = superadmin_mode()

    cond do
      password in [nil, ""] ->
        Logger.warning("superadmin_bootstrap.skip reason=DASH_SUPERADMIN_PASSWORD not set")

      not (first_start?() or lockout?(enabled_superadmins(), mode)) ->
        Logger.info("superadmin_bootstrap.skip reason=superadmin already present")

      true ->
        disabled = mode == "disabled"

        insert_seed(%{
          username: "superadmin",
          # Rights management only: view_only role, the flag carries the power.
          role: @role_view_only,
          password_hash: Password.hash(password),
          is_superadmin: true,
          disabled: disabled
        })

        Logger.info("superadmin_bootstrap.created username=superadmin disabled=#{disabled}")
    end

    :ok
  end

  # -- shared ----------------------------------------------------------------

  # Derive the seed's enabled/disabled state from the mode, exactly as
  # _apply_seed_state did: "auto" follows whether a real counterpart exists.
  defp apply_seed_state(boot, opts) do
    mode = Keyword.fetch!(opts, :mode)
    event = Keyword.fetch!(opts, :event)

    want_disabled =
      case mode do
        "disabled" -> true
        "enabled" -> false
        _auto -> Keyword.fetch!(opts, :supplanted)
      end

    cond do
      want_disabled and not boot.disabled ->
        Repo.update_all(from(u in User, where: u.id == ^boot.id), set: [disabled: true])
        Logger.info("#{event}.disabled username=#{boot.username} mode=#{mode}")

      not want_disabled and boot.disabled ->
        # Break-glass: re-enable AND reset the password from the env, bumping
        # password_version so any lingering session for it dies.
        sets =
          case Keyword.fetch!(opts, :env_password) do
            pw when pw in [nil, ""] ->
              [disabled: false]

            pw ->
              [
                disabled: false,
                password_hash: Password.hash(pw),
                password_version: boot.password_version + 1
              ]
          end

        Repo.update_all(from(u in User, where: u.id == ^boot.id), set: sets)
        Logger.warning("#{event}.breakglass username=#{boot.username} mode=#{mode}")

      true ->
        Logger.info("#{event}.unchanged username=#{boot.username} disabled=#{boot.disabled}")
    end

    :ok
  end

  defp insert_seed(attrs) do
    %User{}
    |> Ecto.Changeset.change(
      Map.merge(attrs, %{
        password_version: 1,
        is_bootstrap: true,
        totp_enabled: false,
        created_at: now()
      })
    )
    |> Repo.insert()
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  defp seed_row(superadmin?) do
    Repo.one(from(u in User, where: u.is_bootstrap == true and u.is_superadmin == ^superadmin?))
  end

  defp first_start?, do: Repo.aggregate(User, :count) == 0

  # A seed is (re)created when no enabled counterpart remains at all, unless it
  # was explicitly retired with *_DISABLED=1.
  defp lockout?(enabled_count, mode), do: enabled_count == 0 and mode != "disabled"

  defp enabled_admins do
    Repo.aggregate(from(u in User, where: u.role == @role_admin and u.disabled == false), :count)
  end

  defp enabled_superadmins do
    Repo.aggregate(
      from(u in User, where: u.is_superadmin == true and u.disabled == false),
      :count
    )
  end

  defp other_enabled_admins do
    from(u in User,
      where: u.role == @role_admin and u.disabled == false and u.is_bootstrap == false
    )
    |> Repo.aggregate(:count)
  end

  defp other_enabled_superadmins do
    from(u in User,
      where: u.is_superadmin == true and u.disabled == false and u.is_bootstrap == false
    )
    |> Repo.aggregate(:count)
  end

  @doc "Resolve a *_DISABLED env value to \"auto\" | \"enabled\" | \"disabled\"."
  def resolve_mode(raw) do
    case raw |> to_string() |> String.trim() |> String.downcase() do
      v when v in ~w(1 true yes on) -> "disabled"
      v when v in ~w(0 false no off) -> "enabled"
      _ -> "auto"
    end
  end

  defp admin_mode, do: resolve_mode(Application.get_env(:orbit, :admin_disabled_raw, "auto"))

  defp superadmin_mode,
    do: resolve_mode(Application.get_env(:orbit, :superadmin_disabled_raw, "auto"))

  defp admin_password, do: Application.get_env(:orbit, :admin_password)
  defp superadmin_password, do: Application.get_env(:orbit, :superadmin_password)
end
