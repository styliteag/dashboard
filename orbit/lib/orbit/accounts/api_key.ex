defmodule Orbit.Accounts.ApiKey do
  @moduledoc """
  Read-only mirror of the `api_keys` table.

  Service-account keys (`orbit_` prefix), read-only by construction. Only the
  SHA-256 of the token is stored (`key_hash`); `key_enc` optionally keeps the
  Fernet-encrypted token for revealable keys (Checkmk).

  Scoping semantics (change-frozen, inverse of users — see Orbit.Auth.Scope):
  a key bound to zero groups is GLOBAL; a user in zero groups sees NOTHING.

  Schema is owned by Alembic until cutover — mirror columns here, never
  migrate (docs/elixir-liveview-rewrite.md §7).
  """

  use Ecto.Schema

  schema "api_keys" do
    field :name, :string
    field :key_hash, :string, redact: true
    field :prefix, :string
    field :last_used_at, Orbit.Ecto.UtcDateTime
    field :revoked_at, Orbit.Ecto.UtcDateTime
    field :revealable, :boolean
    field :key_enc, :binary, redact: true
    field :purpose, :string

    field :created_at, Orbit.Ecto.UtcDateTime

    # Join column is `apikey_id` (no underscore) — Ecto would derive api_key_id.
    many_to_many :groups, Orbit.Accounts.Group,
      join_through: "apikey_groups",
      join_keys: [apikey_id: :id, group_id: :id]
  end

  @spec group_id_set(t()) :: MapSet.t(integer())
  def group_id_set(%__MODULE__{groups: groups}) when is_list(groups) do
    MapSet.new(groups, & &1.id)
  end

  @type t :: %__MODULE__{}
end
