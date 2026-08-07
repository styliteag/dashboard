defmodule Orbit.Alerts.State do
  @moduledoc """
  One alert occurrence (docs/alert-lifecycle.md DR-LC1): identity is
  `(instance_id, check_key)` while `resolved_at` is NULL. Reappearing
  after a resolve creates a NEW row — a returned alert is a new incident
  and starts un-acked (DR-LC4).
  """

  use Ecto.Schema

  @type t :: %__MODULE__{}

  schema "alert_states" do
    field :instance_id, :integer
    field :check_key, :string
    field :severity, :integer
    field :first_seen_at, Orbit.Ecto.UtcDateTime
    field :last_seen_at, Orbit.Ecto.UtcDateTime
    field :acked_by, :string
    field :acked_at, Orbit.Ecto.UtcDateTime
    field :snoozed_until, Orbit.Ecto.UtcDateTime
    field :resolved_at, Orbit.Ecto.UtcDateTime
  end
end
