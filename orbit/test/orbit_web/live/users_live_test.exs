defmodule OrbitWeb.UsersLiveTest do
  @moduledoc "Auth gate (DB-free); superadmin rights overview proven in the live E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/users")
  end
end
