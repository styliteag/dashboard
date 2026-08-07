defmodule OrbitWeb.AvailabilityLiveTest do
  @moduledoc "Auth gate (DB-free house style, like the other list pages)."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/availability")
  end

  test "the old /uptime URL still reaches the renamed page", %{conn: conn} do
    # Unauthenticated: the auth plug fires first — the route existing at all
    # is what this asserts (a removed route would 404, not redirect).
    conn = get(conn, ~p"/uptime")
    assert redirected_to(conn) == ~p"/login"
  end
end
