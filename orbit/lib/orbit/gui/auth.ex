defmodule Orbit.GUI.Auth do
  @moduledoc """
  Self-contained signed tokens for the GUI-proxy auth gate (§18) — port of
  agent_hub/gui_auth.py, wire-compatible so a token minted by either stack
  verifies on the other (both derive the same HMAC key from the shared
  DASH_MASTER_KEY).

  The GUI origin (gui-<id> subdomain / dev port) is cross-origin from the
  dashboard, so the session cookie can't gate it. The dashboard mints a
  short-lived handoff token; the GUI origin exchanges it for an `orbit_gui`
  cookie; Caddy forward_auth verifies that cookie on every request.

  Verification is zero-I/O (HMAC only, no DB/hub), and the token binds
  instance_id so a cookie for one firewall can't satisfy another's gate
  (cross-tenant defense). Cross-language vectors in the test prove the wire
  format matches python exactly.
  """

  @cookie_name "orbit_gui"

  def cookie_name, do: @cookie_name

  # Dedicated HMAC key derived from the Fernet master key (already secret),
  # sha256("orbit-gui-proxy:" <> master_key) — byte-identical to _secret().
  defp secret do
    :crypto.hash(:sha256, "orbit-gui-proxy:" <> Orbit.Crypto.master_key!())
  end

  defp b64(raw), do: Base.url_encode64(raw, padding: false)
  defp unb64(s), do: Base.url_decode64(s, padding: false)

  @doc "Sign (instance_id, now+ttl) → opaque token (handoff + cookie)."
  def sign(instance_id, ttl_seconds, now \\ nil) do
    now = now || System.os_time(:second)
    payload = "#{instance_id}:#{now + ttl_seconds}"
    sig = :crypto.mac(:hmac, :sha256, secret(), payload)
    "#{b64(payload)}.#{b64(sig)}"
  end

  @doc "instance_id if the token is well-formed, authentic and unexpired, else nil."
  def verify(token, now \\ nil)

  def verify(token, now) when is_binary(token) do
    now = now || System.os_time(:second)

    with [payload_b64, sig_b64] <- String.split(token, ".", parts: 2),
         {:ok, payload} <- unb64(payload_b64),
         {:ok, sig} <- unb64(sig_b64),
         expected = :crypto.mac(:hmac, :sha256, secret(), payload),
         true <- constant_time_equal?(sig, expected),
         [instance_s, exp_s] <- String.split(payload, ":"),
         {instance_id, ""} <- Integer.parse(instance_s),
         {exp, ""} <- Integer.parse(exp_s),
         true <- exp >= now do
      instance_id
    else
      _ -> nil
    end
  end

  def verify(_non_binary, _now), do: nil

  # hash_equals raises on unequal sizes; python's compare_digest just returns
  # False. Guard the size so a short/garbage sig is a clean reject.
  defp constant_time_equal?(a, b) when byte_size(a) == byte_size(b),
    do: :crypto.hash_equals(a, b)

  defp constant_time_equal?(_a, _b), do: false
end
