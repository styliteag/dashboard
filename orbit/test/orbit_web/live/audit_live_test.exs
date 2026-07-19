defmodule OrbitWeb.AuditLiveTest do
  @moduledoc "Admin-gate on the audit route (DB-free); the row view is proven live."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/audit")
  end
end
