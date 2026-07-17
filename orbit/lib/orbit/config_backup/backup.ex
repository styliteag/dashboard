defmodule Orbit.ConfigBackup.Backup do
  @moduledoc """
  One stored firewall config version. `content_enc` is a Fernet token (the XML
  is encrypted at rest, decrypted only on read). Newest `keep_per_instance/0`
  per instance are kept. Schema is Alembic-owned (table config_backups).
  """

  use Ecto.Schema

  @type t :: %__MODULE__{}

  schema "config_backups" do
    field :instance_id, :integer
    field :collected_at, Orbit.Ecto.UtcDateTime
    field :sha256, :string
    field :bytes, :integer
    field :source, :string
    field :content_enc, :binary
  end
end
