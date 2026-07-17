defmodule OrbitWeb.SettingsLiveTest do
  @moduledoc "Admin-gate on the settings route (DB-free); edit flow proven in the live E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/settings")
  end
end
