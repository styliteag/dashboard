defmodule OrbitWeb.InstancesLiveTest do
  @moduledoc "Auth gate (DB-free); scoped list render proven in the live E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/instances")
  end
end
