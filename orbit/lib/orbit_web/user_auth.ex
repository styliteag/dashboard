defmodule OrbitWeb.UserAuth do
  @moduledoc """
  Session-based browser auth, mirroring the python session semantics
  (auth/routes.py + auth/deps.py):

  - A full session carries `user_id`, `password_version` and `mfa_passed`.
    `password_version` is checked against the DB row on every request — a
    password change invalidates every existing session (US-1.2).
  - The password step alone stores only `mfa_user_id`/`mfa_pw_version`
    (pending-MFA state, no session privileges).
  - Disabled accounts die on the next request, not just at login.
  - The bootstrap admin is the only password-only account (`mfa_passed` is
    set at login for it because `Accounts.login_step/3` returned `:done`).
  """

  use OrbitWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  alias Orbit.Accounts
  alias Orbit.Accounts.User

  @doc "Mint the fully-authenticated session (after the second factor passed)."
  def log_in_user(conn, user) do
    # Session-registry bookkeeping (DR-AL3): the sid rides in the cookie so
    # requests can stamp last_seen; the registry is NOT consulted for auth.
    sid = Orbit.Access.Store.new_sid()
    Orbit.Access.Store.open_session(sid, user.id, Orbit.Net.client_ip(conn))

    conn
    |> renew_session()
    |> put_session(:user_id, user.id)
    |> put_session(:password_version, user.password_version)
    |> put_session(:mfa_passed, true)
    |> put_session(:sid, sid)
  end

  @doc "Store the pending-MFA state: password passed, second factor missing."
  def put_pending_mfa(conn, user) do
    conn
    |> renew_session()
    |> put_session(:mfa_user_id, user.id)
    |> put_session(:mfa_pw_version, user.password_version)
  end

  @doc """
  Load the pending-MFA user, or nil. The stored password_version must still
  match — a password change between the steps voids the pending state.
  """
  def pending_mfa_user(conn) do
    with user_id when is_integer(user_id) <- get_session(conn, :mfa_user_id),
         %Accounts.User{} = user <- Accounts.get_user(user_id),
         true <- get_session(conn, :mfa_pw_version) == user.password_version,
         false <- user.disabled do
      user
    else
      _ -> nil
    end
  end

  def log_out_user(conn) do
    # Close the registry row BEFORE the session is renewed away (DR-AL3).
    Orbit.Access.Store.close_session(get_session(conn, :sid), "logout")

    conn
    |> renew_session()
    |> redirect(to: ~p"/login")
  end

  @doc """
  Plug: count this request in the access accounting (DR-AL2) — runs after
  fetch_current_user, records at response time so the status is known. The
  buffers are bounded casts; anon requests aggregate without IP sample rows
  (DR-AL8). WebSocket upgrades count as one access via their controller GET.
  """
  def track_access(conn, _opts) do
    register_before_send(conn, fn conn ->
      case conn.assigns[:principal] || conn.assigns[:current_user] do
        # An orbit_ API key is a principal in its own right — Checkmk and
        # Prometheus scrapers were invisible in the access log, so nobody
        # could tell whether a key was still in use before purging it.
        # pkey is the key id — the Access page resolves the display name
        # from it, and opts only carry keys the store actually reads.
        %Orbit.Accounts.ApiKey{id: id} ->
          Orbit.Access.Store.record_request(
            "apikey",
            to_string(id),
            Orbit.Net.client_ip(conn),
            conn.method,
            conn.request_path,
            conn.status
          )

        %User{id: id} ->
          Orbit.Access.Store.record_request(
            "user",
            to_string(id),
            Orbit.Net.client_ip(conn),
            conn.method,
            conn.request_path,
            conn.status,
            user_id: id,
            sid: get_session(conn, :sid)
          )

        _ ->
          # No IP for anon — aggregate only (DR-AL8, http_log.py parity).
          Orbit.Access.Store.record_request(
            "anon",
            "anon",
            nil,
            conn.method,
            conn.request_path,
            conn.status
          )
      end

      conn
    end)
  end

  @doc "Plug: resolve assigns.current_user from the session (or nil)."
  def fetch_current_user(conn, _opts) do
    with user_id when is_integer(user_id) <- get_session(conn, :user_id),
         true <- get_session(conn, :mfa_passed) == true,
         %Accounts.User{} = user <- Accounts.get_user(user_id),
         true <- get_session(conn, :password_version) == user.password_version,
         false <- user.disabled do
      assign(conn, :current_user, user)
    else
      _ -> assign(conn, :current_user, nil)
    end
  end

  @doc "Plug: require a fully-authenticated session, else redirect to /login."
  def require_authenticated_user(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> put_flash(:error, "Please sign in.")
      |> redirect(to: ~p"/login")
      |> halt()
    end
  end

  @doc """
  LiveView on_mount hook: assign :current_user from the session, or redirect
  to /login. Same validation as fetch_current_user (password_version + not
  disabled). Use as `on_mount OrbitWeb.UserAuth` in a live route.
  """
  def on_mount(:default, _params, session, socket) do
    user = live_user_from_session(session)

    if user do
      {:cont, Phoenix.Component.assign(socket, :current_user, user)}
    else
      {:halt, Phoenix.LiveView.redirect(socket, to: ~p"/login")}
    end
  end

  # Admin-only live routes (config surfaces). Non-admins bounce to home.
  def on_mount(:require_admin, _params, session, socket) do
    case live_user_from_session(session) do
      %User{role: "admin"} = user ->
        {:cont, Phoenix.Component.assign(socket, :current_user, user)}

      %User{} ->
        {:halt, Phoenix.LiveView.redirect(socket, to: ~p"/")}

      _ ->
        {:halt, Phoenix.LiveView.redirect(socket, to: ~p"/login")}
    end
  end

  # Admin OR superadmin (DR-AL1): the audit/access oversight surface. Plain
  # require_admin would lock the superadmin out — their role is view_only
  # (rights management only), yet login/block oversight is exactly their
  # domain (python live-incident 2026-07-14: seed superadmin got 403).
  def on_mount(:require_admin_or_superadmin, _params, session, socket) do
    case live_user_from_session(session) do
      %User{} = user when user.role == "admin" or user.is_superadmin ->
        {:cont, Phoenix.Component.assign(socket, :current_user, user)}

      %User{} ->
        {:halt, Phoenix.LiveView.redirect(socket, to: ~p"/")}

      _ ->
        {:halt, Phoenix.LiveView.redirect(socket, to: ~p"/login")}
    end
  end

  # Superadmin-only live routes (rights management). Non-superadmins bounce home.
  def on_mount(:require_superadmin, _params, session, socket) do
    case live_user_from_session(session) do
      %User{is_superadmin: true} = user ->
        {:cont, Phoenix.Component.assign(socket, :current_user, user)}

      %User{} ->
        {:halt, Phoenix.LiveView.redirect(socket, to: ~p"/")}

      _ ->
        {:halt, Phoenix.LiveView.redirect(socket, to: ~p"/login")}
    end
  end

  defp live_user_from_session(session) do
    with user_id when is_integer(user_id) <- session["user_id"],
         true <- session["mfa_passed"] == true,
         %User{} = user <- Accounts.get_user(user_id),
         true <- session["password_version"] == user.password_version,
         false <- user.disabled do
      user
    else
      _ -> nil
    end
  end

  @doc """
  Plug: resolve `assigns.principal` for read-only endpoints — a session user
  OR a valid `orbit_` api key (read-only by construction). Mirror of
  read_principal (auth/deps.py). API keys are rejected on non-GET methods.

  ApiKey with zero group bindings is GLOBAL; a session user is scoped to their
  groups (invariant 1). 401 when neither authenticates.
  """
  def read_principal(conn, _opts) do
    case bearer_orbit_key(conn) do
      nil ->
        if conn.assigns[:current_user] do
          Plug.Conn.assign(conn, :principal, conn.assigns.current_user)
        else
          conn
          |> put_status(401)
          |> Phoenix.Controller.json(%{detail: "not authenticated"})
          |> halt()
        end

      token ->
        resolve_api_key(conn, token)
    end
  end

  defp bearer_orbit_key(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token | _] ->
        t = String.trim(token)
        if String.starts_with?(t, "orbit_"), do: t, else: nil

      _ ->
        nil
    end
  end

  defp resolve_api_key(conn, token) do
    case Accounts.get_api_key_by_token(token) do
      nil ->
        conn |> put_status(401) |> Phoenix.Controller.json(%{detail: "invalid API key"}) |> halt()

      _key when conn.method not in ~w(GET HEAD OPTIONS) ->
        conn
        |> put_status(403)
        |> Phoenix.Controller.json(%{detail: "API key is read-only"})
        |> halt()

      key ->
        Plug.Conn.assign(conn, :principal, key)
    end
  end

  @doc "Plug: JSON 401 for unauthenticated api calls (no redirect dance)."
  def require_authenticated_api(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> put_status(401)
      |> Phoenix.Controller.json(%{detail: "not authenticated"})
      |> halt()
    end
  end

  @doc "Plug: JSON 403 for a non-write role on an api mutation (require_write parity)."
  def require_write_api(conn, _opts) do
    case conn.assigns[:current_user] do
      %{role: role} when role in ~w(admin user) ->
        conn

      %{} ->
        conn
        |> put_status(403)
        |> Phoenix.Controller.json(%{detail: "write access required"})
        |> halt()

      _ ->
        conn
        |> put_status(401)
        |> Phoenix.Controller.json(%{detail: "not authenticated"})
        |> halt()
    end
  end

  @doc "Plug: send signed-in users away from the login pages."
  def redirect_if_authenticated(conn, _opts) do
    if conn.assigns[:current_user] do
      conn |> redirect(to: ~p"/") |> halt()
    else
      conn
    end
  end

  # Session-fixation defense: fresh session id, nothing carried over.
  defp renew_session(conn) do
    conn
    |> configure_session(renew: true)
    |> clear_session()
  end
end
