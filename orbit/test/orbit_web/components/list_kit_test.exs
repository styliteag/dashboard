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
end
