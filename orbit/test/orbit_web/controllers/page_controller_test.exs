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
end
