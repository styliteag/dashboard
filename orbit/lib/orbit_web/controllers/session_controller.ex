defmodule OrbitWeb.SessionController do
  @moduledoc """
  Login/logout flow — controller-rendered forms (no LiveView here: session
  cookies can only be written from a plain request/response cycle).

  Mirrors the python /auth/login two-step contract: password → challenge
  (`:done` bootstrap-only | `:verify` → TOTP page | `:enroll` → blocked until
  enrollment ships), TOTP → session. Rate limiting and constant-time
  verification live in Orbit.Accounts / Orbit.Auth.
  """

  use OrbitWeb, :controller

  alias Orbit.Accounts
  alias Orbit.Auth.LoginLimiter
  alias OrbitWeb.UserAuth

  plug :put_layout, false

  def new(conn, _params) do
    render(conn, :new, error: nil)
  end

  def create(conn, %{"username" => username, "password" => password}) do
    case Accounts.login(username, password, client_ip(conn)) do
      {:ok, {:done, user}} ->
        LoginLimiter.record_success(client_ip(conn))

        conn
        |> UserAuth.log_in_user(user)
        |> redirect(to: ~p"/")

      {:ok, {:verify, user, %{totp: true}}} ->
        conn
        |> UserAuth.put_pending_mfa(user)
        |> redirect(to: ~p"/login/totp")

      {:ok, {:verify, user, _factors}} ->
        # Passkey-only account — WebAuthn ships later in the rewrite; TOTP
        # form still renders so a totp+passkey user is never locked out.
        conn
        |> UserAuth.put_pending_mfa(user)
        |> redirect(to: ~p"/login/totp")

      {:ok, {:enroll, _user}} ->
        # Mandatory-2FA enrollment UI is not ported yet: fail closed with a
        # clear message instead of minting a factor-less session.
        render(conn, :new, error: "This account must enroll 2FA in the legacy UI first.")

      {:error, :rate_limited} ->
        conn
        |> put_status(429)
        |> render(:new, error: "Too many failed attempts; try again later.")

      {:error, _reason} ->
        # invalid_credentials and account_disabled share one message — no
        # account-state oracle on the login form.
        render(conn, :new, error: "Invalid credentials.")
    end
  end

  def totp_form(conn, _params) do
    case UserAuth.pending_mfa_user(conn) do
      nil -> redirect_to_login(conn)
      _user -> render(conn, :totp, error: nil)
    end
  end

  def totp_verify(conn, %{"code" => code}) do
    case UserAuth.pending_mfa_user(conn) do
      nil ->
        redirect_to_login(conn)

      user ->
        if Accounts.verify_totp(user, code) do
          LoginLimiter.record_success(client_ip(conn))

          conn
          |> UserAuth.log_in_user(user)
          |> redirect(to: ~p"/")
        else
          # Failed second factor counts toward the same per-IP limiter as a
          # failed password (python parity: brute-forcing codes locks the IP).
          LoginLimiter.record_failure(client_ip(conn))
          render(conn, :totp, error: "Invalid code.")
        end
    end
  end

  def delete(conn, _params) do
    UserAuth.log_out_user(conn)
  end

  defp redirect_to_login(conn), do: conn |> redirect(to: ~p"/login")

  # Dev stack runs without a trusted proxy (DASH_TRUSTED_PROXY_HOPS=0 mindset);
  # the full client_ip port with hop handling lands with the access-log port.
  defp client_ip(conn), do: conn.remote_ip |> :inet.ntoa() |> to_string()
end
