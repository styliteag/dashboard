defmodule OrbitWeb.PageController do
  use OrbitWeb, :controller

  alias Orbit.Accounts.User

  # Landing = the fleet, whenever the account can see one (UI/UX review
  # U-M1, decision E1): /hub is about the dashboard's transport, not the
  # fleet, so sending admins there made "home" mean different things per
  # role. Now every account with instance visibility lands on /instances.
  #
  # The fallbacks stay: /hub is admin-only and require_admin bounces
  # non-admins back to "/" — a plain "/" -> "/hub" redirect is an infinite
  # loop for them. And instance pages are empty for an account without
  # groups (Scope: zero groups = zero instances), so a group-less admin
  # still goes to /hub and a pure superadmin to /users — the first page
  # each can actually use.
  def home(conn, _params) do
    redirect(conn, to: landing(conn.assigns.current_user))
  end

  # /uptime -> /availability (UI/UX review E2 rename); route kept so old
  # bookmarks and muscle memory survive.
  def uptime(conn, _params), do: redirect(conn, to: ~p"/availability")

  @doc "Public for the DB-free unit test — routing rules above."
  def landing(%User{} = user) do
    cond do
      MapSet.size(User.group_id_set(user)) > 0 -> ~p"/instances"
      User.admin?(user) -> ~p"/hub"
      user.is_superadmin -> ~p"/users"
      true -> ~p"/security"
    end
  end
end
