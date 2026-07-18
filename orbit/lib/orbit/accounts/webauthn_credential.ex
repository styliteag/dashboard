defmodule Orbit.Accounts.WebauthnCredential do
  @moduledoc """
  Mirror of the `webauthn_credentials` table (one passkey; a user may have
  several). Columns carried over from backend db/models.py:

  - `credential_id` — the authenticator's credential id, base64url (no padding),
    unique per credential.
  - `public_key` — the **raw COSE** public-key bytes exactly as they appear in
    the attestation's authenticator data (byte-identical to what py_webauthn
    stores), so a passkey enrolled here stays usable by both stacks during the
    migration window.
  - `sign_count` — clone/replay counter, bumped on each assertion (login slice).

  Schema is owned by Alembic until cutover — mirror columns here, never migrate
  (docs/elixir-liveview-rewrite.md §7). Inserts/deletes live in Orbit.Accounts.
  """

  use Ecto.Schema

  schema "webauthn_credentials" do
    field :user_id, :integer
    field :credential_id, :string
    field :public_key, :binary, redact: true
    field :sign_count, :integer
    field :name, :string
    field :transports, :string

    field :created_at, Orbit.Ecto.UtcDateTime
    field :last_used_at, Orbit.Ecto.UtcDateTime
  end

  @type t :: %__MODULE__{}
end
