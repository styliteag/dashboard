defmodule Orbit.Accounts.Group do
  @moduledoc """
  Read-only mirror of the `groups` table (Alembic migration 028).

  Instance container: every instance belongs to exactly one group; a user only
  sees instances of groups they are member of (Orbit.Auth.Scope). Group 1
  "default" holds everything predating groups.

  Schema is owned by Alembic until cutover — mirror columns here, never
  migrate.
  """

  use Ecto.Schema

  schema "groups" do
    field :name, :string

    field :created_at, Orbit.Ecto.UtcDateTime

    many_to_many :users, Orbit.Accounts.User, join_through: "user_groups"
  end
end
