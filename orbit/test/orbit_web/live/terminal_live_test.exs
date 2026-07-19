defmodule OrbitWeb.TerminalLiveTest do
  @moduledoc "Auth gate (DB-free); scoped terminal + PTY punch-through proven in the shell-WS E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/instances/1/terminal")
  end
end
