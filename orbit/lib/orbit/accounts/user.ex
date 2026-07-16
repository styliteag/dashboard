defmodule Orbit.Accounts.User do
  @moduledoc """
  Read-only mirror of the `users` table.

  Semantics carried over from backend db/models.py:
  - `role` taxonomy: "admin" | "user" | "view_only".
  - `is_superadmin` = rights management ONLY (groups/users/memberships) —
    instance visibility still comes solely from group membership, so a pure
    superadmin without groups sees no instances. No bypass, ever.
  - `password_version` bumps on password change to kill existing sessions.
  - `totp_secret_enc` is Fernet-encrypted (Orbit.Crypto.Fernet).

  Schema is owned by Alembic until cutover — mirror columns here, never
  migrate (docs/elixir-liveview-rewrite.md §7).
  """

  use Ecto.Schema

  schema "users" do
    field :username, :string
    field :password_hash, :string, redact: true
    field :password_version, :integer
    field :role, :string
    field :totp_secret_enc, :binary, redact: true
    field :totp_enabled, :boolean
    field :is_bootstrap, :boolean
    field :disabled, :boolean
    field :is_superadmin, :boolean
    field :last_login_ip, :string
    field :last_login_country, :string
    field :last_login_at, Orbit.Ecto.UtcDateTime

    field :created_at, Orbit.Ecto.UtcDateTime

    many_to_many :groups, Orbit.Accounts.Group, join_through: "user_groups"
  end

  @spec admin?(t()) :: boolean()
  def admin?(%__MODULE__{role: role}), do: role == "admin"

  @spec group_id_set(t()) :: MapSet.t(integer())
  def group_id_set(%__MODULE__{groups: groups}) when is_list(groups) do
    MapSet.new(groups, & &1.id)
  end

  @type t :: %__MODULE__{}
end
