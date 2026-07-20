defmodule OrbitWeb.AuditLiveTest do
  @moduledoc "Admin-gate on the audit route (DB-free); the row view is proven live."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/audit")
  end
end

defmodule OrbitWeb.AuditLiveReadFailureTest do
  @moduledoc """
  Mount with no sandbox connection checked out — deliberately NOT ConnCase,
  which hands every test a working one. That is how an unreachable database
  presents to this page.
  """
  use ExUnit.Case, async: true

  test "an unreachable database mounts a flagged empty page, not a crash" do
    # The page's own queries (the audit_log SELECT, the Access aggregates)
    # had no guard at all — only the two lookup helpers did — and a pool
    # checkout EXITS rather than raising, so the page died on every 30s
    # refresh precisely when the database is the thing in trouble.
    socket =
      Phoenix.Component.assign(%Phoenix.LiveView.Socket{},
        current_user: %{id: 1, role: "admin", groups: []}
      )

    {:ok, socket} = OrbitWeb.AuditLive.mount(%{}, %{}, socket)

    # Flagged, not silently empty: "no audit events" and "could not read the
    # audit log" must never look the same on an oversight surface.
    assert socket.assigns.read_error
    assert socket.assigns.rows == []
  end
end
