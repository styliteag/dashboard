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

  @doc "Mint the fully-authenticated session (after the second factor passed)."
  def log_in_user(conn, user) do
    conn
    |> renew_session()
    |> put_session(:user_id, user.id)
    |> put_session(:password_version, user.password_version)
    |> put_session(:mfa_passed, true)
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
    conn
    |> renew_session()
    |> redirect(to: ~p"/login")
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
