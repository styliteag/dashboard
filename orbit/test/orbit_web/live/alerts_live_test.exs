defmodule OrbitWeb.AlertsLiveTest do
  @moduledoc "Auth gate (DB-free); scoped worst-first alert list proven in the live E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/alerts")
  end
end
