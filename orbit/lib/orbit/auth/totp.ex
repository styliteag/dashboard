defmodule Orbit.Auth.TOTP do
  @moduledoc """
  RFC 6238 TOTP — mirror of backend/src/app/auth/totp.py.

  Single 6-digit, 30-second, SHA-1 code (the universal authenticator default).
  Secrets are unpadded base32 strings, stored Fernet-encrypted in
  `users.totp_secret_enc` — existing enrollments must keep validating, proven
  by cross-language vectors in totp_test.exs.

  `verify/3` accepts a small clock-drift window and an optional `:at`
  timestamp so tests are deterministic.
  """

  import Bitwise

  @digits 6
  @period 30

  @spec generate_secret(pos_integer()) :: String.t()
  def generate_secret(num_bytes \\ 20) do
    num_bytes
    |> :crypto.strong_rand_bytes()
    |> Base.encode32(padding: false)
  end

  @spec verify(String.t(), String.t(), keyword()) :: boolean()
  def verify(secret_b32, code, opts \\ []) do
    code = String.trim(code || "")
    window = Keyword.get(opts, :window, 1)
    at = Keyword.get(opts, :at, System.os_time(:second))

    if valid_code_format?(code) do
      counter = div(trunc(at), @period)

      Enum.any?(-window..window, fn drift ->
        :crypto.hash_equals(hotp(secret_b32, counter + drift), code)
      end)
    else
      false
    end
  end

  @spec provisioning_uri(String.t(), String.t(), String.t()) :: String.t()
  def provisioning_uri(secret_b32, account, issuer) do
    label = URI.encode("#{issuer}:#{account}", &URI.char_unreserved?/1)

    params =
      "secret=#{secret_b32}&issuer=#{URI.encode(issuer, &URI.char_unreserved?/1)}" <>
        "&algorithm=SHA1&digits=#{@digits}&period=#{@period}"

    "otpauth://totp/#{label}?#{params}"
  end

  defp valid_code_format?(code) do
    byte_size(code) == @digits and code =~ ~r/^\d+$/
  end

  defp hotp(secret_b32, counter) do
    key = Base.decode32!(String.upcase(secret_b32), padding: false)
    digest = :crypto.mac(:hmac, :sha, key, <<counter::unsigned-big-64>>)
    offset = :binary.last(digest) &&& 0x0F
    <<_::binary-size(^offset), truncated::unsigned-big-32, _::binary>> = digest

    (truncated &&& 0x7FFFFFFF)
    |> rem(Integer.pow(10, @digits))
    |> Integer.to_string()
    |> String.pad_leading(@digits, "0")
  end
end
