defmodule OrbitWeb.SystemDashboardTest do
  @moduledoc """
  Gate of the system dashboard (`/admin/dashboard`, LiveDashboard). It shows
  fleet-wide process state, so only the admin role gets in: the HTTP request
  through `require_admin_user`, the LiveView socket through the
  `:require_admin` hook.
  """

  use OrbitWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import OrbitWeb.TestHooks

  test "an admin opens the dashboard and its database statistics", %{conn: conn} do
    conn = login(conn, user!("admin", false))

    assert {:ok, _view, _html} = live(conn, "/admin/dashboard/home")
    assert {:ok, _view, html} = live(conn, "/admin/dashboard/ecto_stats")
    assert html =~ "Orbit.Repo"
  end

  test "other roles, a superadmin and a visitor are turned away", %{conn: conn} do
    for {role, superadmin?} <- [{"user", false}, {"view_only", true}] do
      denied = conn |> login(user!(role, superadmin?)) |> get("/admin/dashboard/home")
      assert redirected_to(denied) == "/"
    end

    assert redirected_to(get(conn, "/admin/dashboard/home")) == "/login"
  end
end
