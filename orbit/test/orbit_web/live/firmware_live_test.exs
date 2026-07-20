defmodule OrbitWeb.FirmwareLiveTest do
  @moduledoc "Auth gate (DB-free); scoped firmware compliance proven in the live E2E."
  use OrbitWeb.ConnCase

  import Phoenix.LiveViewTest

  test "unauthenticated visit redirects to login", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, ~p"/firmware")
  end

  describe "compliance bucket" do
    alias OrbitWeb.FirmwareLive

    test "a failed update check counts as Unknown, not as an update" do
      # The check engine rates a failed check WARN and must keep doing so
      # (four-surface parity). The compliance view must not therefore claim
      # the box has an update waiting — it has no answer at all.
      assert FirmwareLive.bucket(%{state: 1, check_failed: true}) == "unknown"
    end

    test "the ordinary states map straight through" do
      assert FirmwareLive.bucket(%{state: 0, check_failed: false}) == "ok"
      assert FirmwareLive.bucket(%{state: 1, check_failed: false}) == "update"
      assert FirmwareLive.bucket(%{state: 2, check_failed: false}) == "update"
      assert FirmwareLive.bucket(%{state: 3, check_failed: false}) == "unknown"
    end
  end
end
