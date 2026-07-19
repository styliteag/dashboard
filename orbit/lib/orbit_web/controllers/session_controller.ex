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

      {:ok, {:verify, user, _factors}} ->
        # Any enrolled second factor → the /login/totp page, which offers the
        # code form and/or the passkey button per the user's actual factors.
        conn
        |> UserAuth.put_pending_mfa(user)
        |> redirect(to: ~p"/login/totp")

      {:ok, {:enroll, user}} ->
        # Mandatory 2FA, no factor yet: password passed → pending state,
        # enrollment page mints the secret (mfa_routes.setup_totp parity).
        conn
        |> UserAuth.put_pending_mfa(user)
        |> redirect(to: ~p"/login/enroll")

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
      nil ->
        redirect_to_login(conn)

      user ->
        factors = Accounts.factor_state(user)
        render(conn, :totp, error: nil, totp: factors.totp, webauthn: factors.webauthn)
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
          factors = Accounts.factor_state(user)

          render(conn, :totp,
            error: "Invalid code.",
            totp: factors.totp,
            webauthn: factors.webauthn
          )
        end
    end
  end

  # -- Passkey login (webauthn_auth_options / _verify port) ------------------
  # Both run on the pending-MFA session (password already passed). The user's
  # credentials come ONLY from pending_mfa_user — an assertion can never satisfy
  # another account. The challenge is stashed in the session between the calls.

  @wa_challenge :wa_login_challenge

  def passkey_options(conn, _params) do
    case UserAuth.pending_mfa_user(conn) do
      nil ->
        conn |> put_status(401) |> json(%{error: "no pending login"})

      user ->
        case Accounts.list_credentials(user) do
          [] ->
            conn |> put_status(400) |> json(%{error: "no passkey enrolled"})

          creds ->
            {options, challenge} = Orbit.Auth.Webauthn.authentication_options(creds)
            conn |> put_session(@wa_challenge, challenge) |> json(options)
        end
    end
  end

  def passkey_verify(conn, %{"credential" => credential}) do
    user = UserAuth.pending_mfa_user(conn)
    challenge = get_session(conn, @wa_challenge)
    ip = client_ip(conn)

    cond do
      LoginLimiter.locked?(ip) ->
        conn |> put_status(429) |> json(%{error: "too many attempts"})

      is_nil(user) or is_nil(challenge) ->
        conn |> put_status(400) |> json(%{error: "no pending login"})

      true ->
        creds = Accounts.list_credentials(user)

        case Orbit.Auth.Webauthn.verify_authentication(credential, challenge, creds) do
          {:ok, %{credential_id: cred_id, sign_count: sign_count}} ->
            Accounts.record_passkey_use(user, cred_id, sign_count)
            LoginLimiter.record_success(ip)
            audit_login(conn, "ok", user.id, %{"reason" => "passkey"})

            conn
            |> delete_session(@wa_challenge)
            |> UserAuth.log_in_user(user)
            |> json(%{ok: true})

          {:error, _reason} ->
            LoginLimiter.record_failure(ip)
            audit_login(conn, "error", user.id, %{"reason" => "passkey_failed"})
            conn |> put_status(400) |> json(%{error: "passkey verification failed"})
        end
    end
  end

  def passkey_verify(conn, _params),
    do: conn |> put_status(400) |> json(%{error: "missing credential"})

  # TOTP enrollment during login (mandatory 2FA, mfa_routes.py port). Each
  # GET mints a fresh pending secret (enabled stays false until confirmed) —
  # re-loading the page invalidates the previous QR, never a live factor.
  def enroll_form(conn, _params) do
    case UserAuth.pending_mfa_user(conn) do
      nil ->
        redirect_to_login(conn)

      user ->
        {secret, uri} = Orbit.Accounts.begin_totp_enrollment(user)
        render(conn, :enroll, secret: secret, uri: uri, error: nil)
    end
  end

  def enroll_verify(conn, %{"code" => code}) do
    case UserAuth.pending_mfa_user(conn) do
      nil ->
        redirect_to_login(conn)

      user ->
        case Orbit.Accounts.confirm_totp_enrollment(user, code) do
          {:ok, enrolled} ->
            LoginLimiter.record_success(client_ip(conn))
            audit_login(conn, "ok", enrolled.id, %{"reason" => "totp_enrolled"})

            conn
            |> UserAuth.log_in_user(enrolled)
            |> redirect(to: ~p"/")

          {:error, _} ->
            # Failed confirm counts toward the same per-IP limiter as a bad
            # password (python parity: brute-forcing codes locks the IP).
            LoginLimiter.record_failure(client_ip(conn))
            audit_login(conn, "error", user.id, %{"reason" => "invalid_code"})
            {secret, uri} = current_pending_secret(user)
            render(conn, :enroll, secret: secret, uri: uri, error: "Invalid code — try again.")
        end
    end
  end

  # Re-render with the SAME pending secret (the user already scanned it).
  defp current_pending_secret(user) do
    secret = Orbit.Crypto.decrypt!(user.totp_secret_enc)
    issuer = Application.get_env(:orbit, :mfa_issuer, "Orbit Dashboard")
    {secret, Orbit.Auth.TOTP.provisioning_uri(secret, user.username, issuer)}
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

  # Proxy-aware client IP (honours DASH_TRUSTED_PROXY_HOPS). MUST match what the
  # limiter/audit use everywhere else: behind nginx conn.remote_ip is the proxy
  # container IP, so keying the LoginLimiter on it collapses every external
  # client into one bucket — 5 bad logins from anyone would lock out all users.
  defp client_ip(conn), do: Orbit.Net.client_ip(conn)
end
