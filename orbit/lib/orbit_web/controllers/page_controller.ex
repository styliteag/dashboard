defmodule OrbitWeb.PageController do
  use OrbitWeb, :controller

  alias Orbit.Accounts.User

  # The old M0 landing page is gone (user decision): the hub roster is the
  # default view after login.
  #
  # It cannot be the landing page for EVERY account, though. /hub is
  # admin-only and require_admin bounces non-admins back to "/" — a plain
  # "/" -> "/hub" redirect is an infinite loop for them. And instance pages
  # are empty for an account without groups (Scope: zero groups = zero
  # instances), so a superadmin would land on a blank list. Send each account
  # to the first page it can actually use.
  def home(conn, _params) do
    redirect(conn, to: landing(conn.assigns.current_user))
  end

  defp landing(%User{} = user) do
    cond do
      User.admin?(user) -> ~p"/hub"
      MapSet.size(User.group_id_set(user)) > 0 -> ~p"/instances"
      user.is_superadmin -> ~p"/users"
      true -> ~p"/security"
    end
  end
end
