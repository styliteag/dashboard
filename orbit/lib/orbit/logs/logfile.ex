defmodule Orbit.Logs.Logfile do
  @moduledoc """
  One agent-pushed log snapshot. Only the newest `KEEP_PER_NAME` per
  (instance_id, name) are kept (see Orbit.Logs.Store). Schema is Alembic-owned
  (table logfiles).
  """

  use Ecto.Schema

  @type t :: %__MODULE__{}

  schema "logfiles" do
    field :instance_id, :integer
    field :name, :string
    field :collected_at, Orbit.Ecto.UtcDateTime
    field :bytes, :integer
    field :content, :string
  end
end
