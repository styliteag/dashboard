defmodule Orbit.Comments.EntityComment do
  @moduledoc """
  Operator note on a check sub-entity (a specific tunnel, monitor, firmware
  line or certificate), keyed per instance by (kind, entity_key). Instance-
  level notes live on Instance.notes instead — not a kind here. Schema is
  Alembic-owned (table entity_comments); unique on (instance_id, kind,
  entity_key) via uq_entity_comment.
  """

  use Ecto.Schema

  @kinds ~w(ipsec connectivity firmware cert)

  @type t :: %__MODULE__{}

  schema "entity_comments" do
    field :instance_id, :integer
    field :kind, :string
    field :entity_key, :string
    field :comment, :string
    field :updated_by, :string
    field :updated_at, Orbit.Ecto.UtcDateTime
  end

  @doc "The four annotatable check families (matches the python CommentKind)."
  def kinds, do: @kinds
end
