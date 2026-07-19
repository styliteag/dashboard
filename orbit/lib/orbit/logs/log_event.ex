defmodule Orbit.Logs.LogEvent do
  @moduledoc """
  One aggregated critical log event for an instance's log, replaced per ingest
  by Orbit.Logs.Store from Orbit.Logs.Events.extract_events. Schema is
  Alembic-owned (table log_events).
  """

  use Ecto.Schema

  @type t :: %__MODULE__{}

  schema "log_events" do
    field :instance_id, :integer
    field :log_name, :string
    field :severity, :integer
    field :program, :string
    field :pattern, :string
    field :sample, :string
    field :count, :integer
    field :last_ts, :string
    field :updated_at, Orbit.Ecto.UtcDateTime
  end
end
