defmodule OrbitWeb.PageControllerTest do
  use OrbitWeb.ConnCase

  test "GET / without a session redirects to the login page", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert redirected_to(conn) == ~p"/login"
  end

  test "GET /login renders the sign-in form", %{conn: conn} do
    conn = get(conn, ~p"/login")
    assert html_response(conn, 200) =~ "STYLiTE Orbit"
    assert html_response(conn, 200) =~ "Sign in"
  end

  test "GET /login/totp without pending-MFA state bounces back to login", %{conn: conn} do
    conn = get(conn, ~p"/login/totp")
    assert redirected_to(conn) == ~p"/login"
  end

  test "POST /logout without a session redirects to login (guarded route)", %{conn: conn} do
    conn = post(conn, ~p"/logout")
    assert redirected_to(conn) == ~p"/login"
  end

  describe "landing/1" do
    alias Orbit.Accounts.{Group, User}
    alias OrbitWeb.PageController

    defp user(attrs) do
      struct!(
        %User{id: 1, username: "u", role: "user", is_superadmin: false, groups: []},
        attrs
      )
    end

    # UI/UX review U-M1 / decision E1: anyone who can see the fleet lands on
    # the fleet — including admins, who used to land on /hub (the transport
    # roster, not the fleet).
    test "an account with groups lands on /instances regardless of role" do
      groups = [%Group{id: 1, name: "A"}]

      assert PageController.landing(user(groups: groups)) == "/instances"
      assert PageController.landing(user(role: "admin", groups: groups)) == "/instances"

      assert PageController.landing(user(is_superadmin: true, groups: groups)) ==
               "/instances"
    end

    test "group-less accounts keep the first-usable-page fallbacks" do
      assert PageController.landing(user(role: "admin", groups: [])) == "/hub"

      assert PageController.landing(user(role: "view_only", is_superadmin: true, groups: [])) ==
               "/users"

      assert PageController.landing(user(role: "user", groups: [])) == "/security"
    end
  end
end
