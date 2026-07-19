defmodule Orbit.Enrollment.EnrollmentCode do
  @moduledoc """
  One-time agent enrollment code (§16). Read/write mirror of the
  `enrollment_codes` table — the admin mints a short-lived code, the agent
  trades it at /api/agent/enroll for the instance's token. Single-use
  (`used_at`) + time-limited (`expires_at`); only the code's SHA-256 is
  stored.

  Alembic owns the schema (no ecto migration); rows are written here.
  """

  use Ecto.Schema

  schema "enrollment_codes" do
    field :code_hash, :string, redact: true
    field :instance_id, :integer
    field :expires_at, Orbit.Ecto.UtcDateTime
    field :used_at, Orbit.Ecto.UtcDateTime

    field :created_at, Orbit.Ecto.UtcDateTime
  end
end
