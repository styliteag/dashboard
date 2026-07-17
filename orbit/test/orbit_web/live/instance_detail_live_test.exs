defmodule OrbitWeb.InstanceDetailLiveTest do
  @moduledoc "Auth gate (DB-free); scoped detail + live metrics proven in the live E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/instances/1")
  end
end
