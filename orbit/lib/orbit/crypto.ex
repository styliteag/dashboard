defmodule Orbit.Crypto do
  @moduledoc """
  Convenience layer over `Orbit.Crypto.Fernet` bound to the configured
  `DASH_MASTER_KEY` — the same key (and thus the same `*_enc` columns) the
  python backend uses. Plaintext never leaves the server process: decrypt at
  the point of use, never into an API/UI payload (CLAUDE.md invariant 3).
  """

  alias Orbit.Crypto.Fernet

  @spec master_key!() :: String.t()
  def master_key! do
    case Application.get_env(:orbit, :dash_master_key) do
      key when is_binary(key) and key != "" ->
        key

      _ ->
        raise Fernet.Error,
              "DASH_MASTER_KEY is not set — required to read the *_enc columns"
    end
  end

  @spec encrypt(String.t()) :: binary()
  def encrypt(plaintext), do: Fernet.encrypt(plaintext, master_key!())

  @spec decrypt(binary()) :: {:ok, String.t()} | {:error, Fernet.Error.t()}
  def decrypt(token), do: Fernet.decrypt(token, master_key!())

  @spec decrypt!(binary()) :: String.t()
  def decrypt!(token), do: Fernet.decrypt!(token, master_key!())
end
