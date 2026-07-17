defmodule OrbitWeb.ConnectivityLiveTest do
  @moduledoc "Auth gate (DB-free); scoped monitor rows proven in the live fleet E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/connectivity")
  end
end
