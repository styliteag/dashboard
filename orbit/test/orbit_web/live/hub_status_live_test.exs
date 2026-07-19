defmodule OrbitWeb.HubStatusLiveTest do
  @moduledoc """
  LiveView auth gate (DB-free). The authenticated render + live roster
  scoping are proven in the live E2E (the test repo points at the empty
  orbit_test DB, so no dash users exist here — house style).
  """
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/hub")
  end
end
