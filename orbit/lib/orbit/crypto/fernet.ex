defmodule Orbit.Crypto.Fernet do
  @moduledoc """
  Fernet (https://github.com/fernet/spec) on top of OTP `:crypto`.

  The Python backend encrypts instance credentials at rest with
  `cryptography.fernet.Fernet` keyed by `DASH_MASTER_KEY`; the existing
  `*_enc` columns must stay readable across the rewrite, so this module is
  wire-compatible by construction and proven by cross-language test vectors
  (test/orbit/crypto/fernet_test.exs — regenerate them from Python, never
  hand-edit). Hex packages for Fernet are unmaintained, hence own module.

  Token layout: base64url( 0x80 || ts:8 big-endian || iv:16 || AES-128-CBC
  ciphertext (PKCS7) || HMAC-SHA256:32 ), HMAC over everything before it.
  Key: base64url of 32 bytes — first 16 signing, last 16 encryption.

  TTL is deliberately not enforced: the Python side never passes `ttl`,
  tokens in the DB are years old and must keep decrypting.
  """

  defmodule Error do
    defexception [:message]
  end

  @version 0x80

  @spec encrypt(String.t(), String.t()) :: String.t()
  def encrypt(plaintext, key) when is_binary(plaintext) and is_binary(key) do
    {sign_key, enc_key} = split_key!(key)
    iv = :crypto.strong_rand_bytes(16)
    ts = System.os_time(:second)
    ciphertext = :crypto.crypto_one_time(:aes_128_cbc, enc_key, iv, pad(plaintext), true)
    body = <<@version, ts::unsigned-big-64, iv::binary, ciphertext::binary>>
    mac = :crypto.mac(:hmac, :sha256, sign_key, body)
    Base.url_encode64(body <> mac)
  end

  @spec decrypt(String.t(), String.t()) :: {:ok, String.t()} | {:error, Error.t()}
  def decrypt(token, key) when is_binary(token) and is_binary(key) do
    {:ok, decrypt!(token, key)}
  rescue
    e in Error -> {:error, e}
  end

  @spec decrypt!(String.t(), String.t()) :: String.t()
  def decrypt!(token, key) when is_binary(token) and is_binary(key) do
    {sign_key, enc_key} = split_key!(key)

    raw =
      case Base.url_decode64(token, padding: true) do
        {:ok, raw} -> raw
        :error -> raise Error, "invalid token: not base64url"
      end

    total = byte_size(raw)

    if total < 1 + 8 + 16 + 16 + 32,
      do: raise(Error, "invalid token: too short")

    body_size = total - 32
    <<body::binary-size(^body_size), mac::binary-32>> = raw
    <<version, _ts::unsigned-big-64, iv::binary-16, ciphertext::binary>> = body

    if version != @version,
      do: raise(Error, "invalid token: unknown version")

    if rem(byte_size(ciphertext), 16) != 0 or byte_size(ciphertext) == 0,
      do: raise(Error, "invalid token: bad ciphertext length")

    expected = :crypto.mac(:hmac, :sha256, sign_key, body)

    if not :crypto.hash_equals(mac, expected),
      do: raise(Error, "decryption failed (wrong key or corrupted data)")

    :aes_128_cbc
    |> :crypto.crypto_one_time(enc_key, iv, ciphertext, false)
    |> unpad!()
  end

  defp split_key!(key) do
    case Base.url_decode64(key, padding: true) do
      {:ok, <<sign_key::binary-16, enc_key::binary-16>>} -> {sign_key, enc_key}
      _ -> raise Error, "invalid Fernet key: must be base64url of 32 bytes"
    end
  end

  defp pad(data) do
    n = 16 - rem(byte_size(data), 16)
    data <> :binary.copy(<<n>>, n)
  end

  defp unpad!(data) do
    n = :binary.last(data)

    with true <- n in 1..16,
         true <- byte_size(data) >= n,
         {body, padding} <- :erlang.split_binary(data, byte_size(data) - n),
         true <- padding == :binary.copy(<<n>>, n) do
      body
    else
      _ -> raise Error, "decryption failed (bad padding)"
    end
  end
end
