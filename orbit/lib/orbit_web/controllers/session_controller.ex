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
        audit_login(conn, "ok", user.id)

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
        audit_login(conn, "error", nil)
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
          audit_login(conn, "ok", user.id)

          conn
          |> UserAuth.log_in_user(user)
          |> redirect(to: ~p"/")
        else
          # Failed second factor counts toward the same per-IP limiter as a
          # failed password (python parity: brute-forcing codes locks the IP).
          LoginLimiter.record_failure(client_ip(conn))
          audit_login(conn, "error", user.id, %{"reason" => "bad_totp"})
          render(conn, :totp, error: "Invalid code.")
        end
    end
  end

  def delete(conn, _params) do
    UserAuth.log_out_user(conn)
  end

  # Change-password self-service (auth/routes.py /password port). Controller,
  # not LiveView: the session cookie must be re-issued with the bumped
  # password_version so THIS client survives while every other session dies.
  def password_form(conn, _params) do
    render(conn, :password, error: nil)
  end

  def password_change(conn, %{"old_password" => old, "new_password" => new} = params) do
    user = conn.assigns.current_user

    cond do
      not Orbit.Auth.Password.verify(old, user.password_hash) ->
        audit_password(conn, user, "error", %{"reason" => "bad_old_password"})
        conn |> put_status(400) |> render(:password, error: "Old password is incorrect.")

      String.length(new) < 8 ->
        render(conn, :password, error: "New password needs at least 8 characters.")

      new != params["confirm_password"] ->
        render(conn, :password, error: "Passwords do not match.")

      true ->
        {:ok, updated} =
          user
          |> Ecto.Changeset.change(%{
            password_hash: Orbit.Auth.Password.hash(new),
            # Invalidates every OTHER session (per-request version check).
            password_version: user.password_version + 1
          })
          |> Orbit.Repo.update()

        audit_password(conn, user, "ok", nil)

        conn
        |> put_session(:password_version, updated.password_version)
        |> put_flash(:info, "Password changed. Other sessions were signed out.")
        |> redirect(to: ~p"/")
    end
  end

  defp audit_password(conn, user, result, detail) do
    Orbit.Audit.write(
      action: "auth.password_change",
      result: result,
      user_id: user.id,
      source_ip: client_ip(conn),
      detail: detail
    )
  end

  defp audit_login(conn, result, user_id, detail \\ nil) do
    Orbit.Audit.write(
      action: "auth.login",
      result: result,
      user_id: user_id,
      source_ip: client_ip(conn),
      detail: detail
    )
  end

  defp redirect_to_login(conn), do: conn |> redirect(to: ~p"/login")

  # Dev stack runs without a trusted proxy (DASH_TRUSTED_PROXY_HOPS=0 mindset);
  # the full client_ip port with hop handling lands with the access-log port.
  defp client_ip(conn), do: conn.remote_ip |> :inet.ntoa() |> to_string()
end
