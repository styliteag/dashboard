defmodule Orbit.GUI.Auth do
  @moduledoc """
  Self-contained signed tokens for the GUI-proxy auth gate (§18) — port of
  agent_hub/gui_auth.py, wire-compatible so a token minted by either stack
  verifies on the other (both derive the same HMAC key from the shared
  DASH_MASTER_KEY).

  The GUI origin (gui-<id> subdomain / dev port) is cross-origin from the
  dashboard, so the session cookie can't gate it. The dashboard mints a
  short-lived handoff token; the GUI origin exchanges it for an `orbit_gui`
  cookie; OrbitWeb.GuiProxy verifies that cookie on every request.

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

  # Purpose tag in a bound token: the 60 s handoff and the 2 h cookie are
  # not interchangeable (a cookie replayed as a handoff would mint a fresh
  # cookie, renewing GUI access forever).
  @purposes %{handoff: "h", cookie: "c"}
  @purpose_tags Map.new(@purposes, fn {k, v} -> {v, k} end)

  @doc """
  Sign a token bound to the user who opened the GUI, his password_version
  and its purpose (`:handoff` or `:cookie`):
  `instance:exp:user:password_version:purpose`. The proxy re-checks the user
  on every request (`Orbit.GUI.authorized?/3`), so a password change, a
  disabled account or a lost membership ends access at once.
  """
  def sign_bound(instance_id, user_id, password_version, purpose, ttl_seconds, now \\ nil)
      when is_map_key(@purposes, purpose) do
    now = now || System.os_time(:second)

    payload =
      "#{instance_id}:#{now + ttl_seconds}:#{user_id}:#{password_version}:#{@purposes[purpose]}"

    sig = :crypto.mac(:hmac, :sha256, secret(), payload)
    "#{b64(payload)}.#{b64(sig)}"
  end

  @doc """
  `{:ok, %{instance_id, user_id, password_version, purpose}}` for an
  authentic, unexpired BOUND token, else `:error` (an unbound token included).
  """
  def verify_bound(token, now \\ nil) do
    with {:ok, payload} <- authentic_payload(token),
         [instance_s, exp_s, user_s, pv_s, tag] <- String.split(payload, ":"),
         {:ok, purpose} <- Map.fetch(@purpose_tags, tag),
         {instance_id, ""} <- Integer.parse(instance_s),
         {user_id, ""} <- Integer.parse(user_s),
         {pv, ""} <- Integer.parse(pv_s),
         true <- unexpired?(exp_s, now) do
      {:ok, %{instance_id: instance_id, user_id: user_id, password_version: pv, purpose: purpose}}
    else
      _ -> :error
    end
  end

  @doc "instance_id if the token is well-formed, authentic and unexpired, else nil."
  def verify(token, now \\ nil)

  def verify(token, now) when is_binary(token) do
    with {:ok, payload} <- authentic_payload(token),
         [instance_s, exp_s] <- String.split(payload, ":"),
         {instance_id, ""} <- Integer.parse(instance_s),
         true <- unexpired?(exp_s, now) do
      instance_id
    else
      _ -> nil
    end
  end

  def verify(_non_binary, _now), do: nil

  defp authentic_payload(token) when is_binary(token) do
    with [payload_b64, sig_b64] <- String.split(token, ".", parts: 2),
         {:ok, payload} <- unb64(payload_b64),
         {:ok, sig} <- unb64(sig_b64),
         expected = :crypto.mac(:hmac, :sha256, secret(), payload),
         true <- constant_time_equal?(sig, expected) do
      {:ok, payload}
    else
      _ -> :error
    end
  end

  defp authentic_payload(_), do: :error

  defp unexpired?(exp_s, now) do
    case Integer.parse(exp_s) do
      {exp, ""} -> exp >= (now || System.os_time(:second))
      _ -> false
    end
  end

  # hash_equals raises on unequal sizes; python's compare_digest just returns
  # False. Guard the size so a short/garbage sig is a clean reject.
  defp constant_time_equal?(a, b) when byte_size(a) == byte_size(b),
    do: :crypto.hash_equals(a, b)

  defp constant_time_equal?(_a, _b), do: false
end
