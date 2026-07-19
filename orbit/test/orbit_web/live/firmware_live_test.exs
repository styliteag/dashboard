defmodule OrbitWeb.FirmwareLiveTest do
  @moduledoc "Auth gate (DB-free); scoped firmware compliance proven in the live E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/firmware")
  end
end
