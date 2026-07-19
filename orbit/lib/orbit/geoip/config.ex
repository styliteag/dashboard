defmodule Orbit.GeoIP.Config do
  @moduledoc """
  Read-only schema for the single-row `geoip_config` table (DR-G6 —
  deliberately not an app_settings row; the surface is superadmin-only).
  Alembic owns the schema; until orbit grows its own superadmin editor the
  python UI stays the writer and orbit only reads.
  """

  use Ecto.Schema

  @primary_key {:id, :integer, autogenerate: false}
  schema "geoip_config" do
    field :enabled, :boolean
    field :countries, :string
    field :whitelist, :string
    field :updated_at, Orbit.Ecto.UtcDateTime
    field :updated_by, :string
  end
end
