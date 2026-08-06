defmodule OrbitWeb.UptimeLiveTest do
  @moduledoc "Auth gate (DB-free house style, like the other list pages)."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/uptime")
  end
end
