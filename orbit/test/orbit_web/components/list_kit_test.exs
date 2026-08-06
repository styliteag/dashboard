defmodule OrbitWeb.Components.ListKitTest do
  @moduledoc """
  The read-only presentation primitives (Access-control house style): a number
  always carries the line saying what it counts, a tally chip carries its
  severity tone, and the honesty note renders whatever caveat the page passes.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias OrbitWeb.Components.ListKit

  test "stat_tile renders label, value and the hint line" do
    html =
      render_component(&ListKit.stat_tile/1,
        label: "Connected",
        value: 5,
        hint: [%{inner_block: fn _, _ -> "agents in your scope, right now" end}]
      )

    assert html =~ "Connected"
    assert html =~ ">5<"
    assert html =~ "agents in your scope, right now"
  end

  test "stat_tile without a hint renders no empty hint line" do
    html = render_component(&ListKit.stat_tile/1, label: "Served agent", value: "3.1.8")

    assert html =~ "3.1.8"
    refute html =~ "text-base-content/50"
  end

  test "count_chip carries the tally and a tone class per severity" do
    chip = fn tone ->
      render_component(&ListKit.count_chip/1, label: "ipsec.tunnel", count: 3, tone: tone)
    end

    assert chip.(:crit) =~ "ipsec.tunnel"
    assert chip.(:crit) =~ "×3"
    assert chip.(:crit) =~ "text-error"
    assert chip.(:warn) =~ "text-warning"
    assert chip.(:ok) =~ "text-primary"
    assert chip.(:neutral) =~ "text-base-content/70"
  end

  test "data_note renders the caveat it is given" do
    html =
      render_component(&ListKit.data_note/1,
        inner_block: [%{inner_block: fn _, _ -> "sampled under floods" end}]
      )

    assert html =~ "sampled under floods"
  end

  # UI/UX review 2026-08-06, U-Q1: pages that mount pre-filtered must say so
  # in words, and the notice is the app's clear-filter affordance.
  test "filter_notice states shown/total and offers Show all" do
    html =
      render_component(&ListKit.filter_notice/1,
        shown: 2,
        total: 8,
        noun: "tunnels",
        filter_label: "down",
        event: "state_filter"
      )

    assert html =~ "Showing 2 of 8 tunnels (down)."
    assert html =~ "Show all"
    assert html =~ ~s|phx-value-bucket="all"|
  end

  # UI/UX review 2026-08-06, D-1/U-Q1: one kpi_tile implementation, and the
  # active filter tile must be announced as pressed.
  test "kpi_tile carries aria-pressed matching its active state" do
    tile = fn active ->
      render_component(&ListKit.kpi_tile/1,
        label: "Down",
        value: 2,
        event: "state_filter",
        value_name: "down",
        active: active
      )
    end

    assert tile.(true) =~ ~s|aria-pressed="true"|
    assert tile.(false) =~ ~s|aria-pressed="false"|
  end

  # UI/UX review 2026-08-06, U-Q5: an empty state without a next step is a
  # dead end — the action slot carries the CTA.
  test "empty_state renders the action slot when given" do
    html =
      render_component(&ListKit.empty_state/1,
        title: "No instances visible for your account.",
        action: [%{inner_block: fn _, _ -> "New instance" end}]
      )

    assert html =~ "No instances visible"
    assert html =~ "New instance"
  end

  # UI/UX review 2026-08-06, A-m10/m12: sortable headers must tell assistive
  # tech the column role and the current sort — the ↑/↓ glyph alone reads as
  # a stray character.
  test "sort_th carries scope and aria-sort for the active and inactive column" do
    th = fn col, sort_col, dir ->
      render_component(&ListKit.sort_th/1,
        col: col,
        label: "Name",
        sort_col: sort_col,
        sort_dir: dir
      )
    end

    active = th.("name", "name", :asc)
    assert active =~ ~s|scope="col"|
    assert active =~ ~s|aria-sort="ascending"|

    assert th.("name", "name", :desc) =~ ~s|aria-sort="descending"|
    assert th.("name", "status", :asc) =~ ~s|aria-sort="none"|
  end

  # UI/UX review 2026-08-06, A-M7: on /instances these two icons are the ONLY
  # path to the tunneled GUI and the root terminal, so they must meet the
  # 24x24 px target floor (WCAG 2.5.8) — p-1.5 + h-3.5 icon = 26px.
  test "webui_link and shell_link render with the enlarged click target" do
    webui =
      render_component(&ListKit.webui_link/1, instance_id: 1, openable: true)

    shell =
      render_component(&ListKit.shell_link/1, instance_id: 1, shell_enabled: true)

    assert webui =~ "p-1.5"
    assert shell =~ "p-1.5"
  end
end
