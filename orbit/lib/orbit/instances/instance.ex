defmodule Orbit.Instances.Instance do
  @moduledoc """
  Read-only mirror of the `instances` table (the columns the rewrite needs so
  far — extend alongside the features that consume them).

  Semantics carried over from backend db/models.py:
  - every instance belongs to exactly one group (visibility scoping);
  - `*_enc` columns are Fernet-encrypted (Orbit.Crypto.Fernet), decrypted only
    at client construction, never exposed by any API/UI;
  - soft-delete via `deleted_at` (historical metrics stay linked);
  - `base_url` may hold several comma-separated URLs — the first is the
    canonical API endpoint (see `primary_base_url/1`).

  Schema is owned by Alembic until cutover — mirror columns here, never
  migrate.
  """

  use Ecto.Schema

  schema "instances" do
    field :name, :string
    field :group_id, :integer
    field :slug, :string
    field :base_url, :string
    field :api_key_enc, :binary, redact: true
    field :api_secret_enc, :binary, redact: true
    field :ca_bundle, :string
    field :ssl_verify, :boolean
    # direct = poll the API; push = agent pushes via the hub; relay = API
    # through the agent tunnel (docs/agent-architecture.md DR-1).
    field :transport, :string
    field :device_type, :string
    field :poll_interval_seconds, :integer
    field :push_interval_seconds, :integer
    field :agent_token, :string, redact: true
    field :agent_last_seen, Orbit.Ecto.UtcDateTime
    field :gui_login_enabled, :boolean
    field :shell_enabled, :boolean
    field :ssh_enabled, :boolean
    field :ssh_port, :integer
    field :ssh_user, :string
    field :ssh_key_enc, :binary, redact: true
    field :ssh_host_key, :string
    field :location, :string
    field :notes, :string
    field :tags, {:array, :string}
    field :ping_url, :string
    field :maintenance, :boolean
    field :firmware_locked, :boolean
    field :last_success_at, Orbit.Ecto.UtcDateTime
    field :last_error_at, Orbit.Ecto.UtcDateTime
    field :last_error_message, :string
    field :status_snapshot, :map
    field :deleted_at, Orbit.Ecto.UtcDateTime

    field :created_at, Orbit.Ecto.UtcDateTime
    field :updated_at, Orbit.Ecto.UtcDateTime

    belongs_to :group, Orbit.Accounts.Group, define_field: false
  end

  @spec agent_mode?(t()) :: boolean()
  def agent_mode?(%__MODULE__{transport: transport}), do: transport == "push"

  @spec primary_base_url(t()) :: String.t()
  def primary_base_url(%__MODULE__{base_url: base_url}) do
    base_url |> String.split(",", parts: 2) |> hd() |> String.trim()
  end

  @type t :: %__MODULE__{}
end
