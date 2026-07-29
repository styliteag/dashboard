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

  describe "bulk-update eligibility (FirmwareCompliancePage parity)" do
    alias OrbitWeb.FirmwareLive

    defp row(overrides) do
      Map.merge(
        %{
          id: 1,
          upgrade_available: true,
          firmware_locked: false,
          agent_mode: true,
          upgrade_major_version: nil
        },
        Map.new(overrides)
      )
    end

    test "eligible needs a pending update and an unlocked box" do
      assert FirmwareLive.eligible?(row(%{}))
      refute FirmwareLive.eligible?(row(%{upgrade_available: false}))
      refute FirmwareLive.eligible?(row(%{firmware_locked: true}))
    end

    test "series upgrade additionally needs agent mode and a resolved target" do
      assert FirmwareLive.series_eligible?(row(%{upgrade_major_version: "25.7"}))
      refute FirmwareLive.series_eligible?(row(%{}))
      refute FirmwareLive.series_eligible?(row(%{upgrade_major_version: ""}))

      refute FirmwareLive.series_eligible?(
               row(%{upgrade_major_version: "25.7", agent_mode: false})
             )

      refute FirmwareLive.series_eligible?(
               row(%{upgrade_major_version: "25.7", firmware_locked: true})
             )
    end

    test "bulk targets are the intersection of selection and eligible visible rows" do
      rows = [
        row(%{id: 1}),
        row(%{id: 2, upgrade_major_version: "25.7"}),
        row(%{id: 3, firmware_locked: true}),
        row(%{id: 4, upgrade_available: false})
      ]

      # id 5 is selected but no longer visible (filtered away) — never acted on.
      selected = MapSet.new([1, 2, 3, 4, 5])

      assert FirmwareLive.bulk_targets(rows, selected, "firmware_update") == [1, 2]
      assert FirmwareLive.bulk_targets(rows, selected, "firmware_upgrade") == [2]
    end

    test "an empty selection yields no targets" do
      assert FirmwareLive.bulk_targets([row(%{})], MapSet.new(), "firmware_update") == []
    end
  end
end
