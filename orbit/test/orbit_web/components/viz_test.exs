defmodule OrbitWeb.Components.VizTest do
  @moduledoc """
  The shared viz vocabulary's RULES (docs/dataviz-language.md DR-DV2):
  absence renders grey, never zero; colours only flip alongside a named
  threshold; lanes keep hatch + dim + sr-only.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias OrbitWeb.Components.Viz

  describe "timeline_lane" do
    test "segments carry colour, hatch, dim and sr-only label" do
      html =
        render_component(&Viz.timeline_lane/1,
          segments: [
            %{state: :down, left: 0, width: 50, label: "down 08-06 14:02–14:37"},
            %{state: :up, left: 50, width: 50, label: nil}
          ]
        )

      assert html =~ "lane-hatch-down"
      assert html =~ "opacity-60"
      refute html =~ ~r/opacity-60[^>]*left: 50/
      assert html =~ "down 08-06 14:02–14:37"
      assert html =~ "sr-only"
    end

    test "dim_resolved: false keeps full chroma (dialog windows)" do
      html =
        render_component(&Viz.timeline_lane/1,
          dim_resolved: false,
          segments: [%{state: :down, left: 0, width: 50, label: nil}]
        )

      refute html =~ "opacity-60"
    end

    test "unknown states fall to the neutral no-data colour" do
      assert Viz.lane_color(:weird) == "bg-neutral"
      assert Viz.lane_color(:partial) =~ "lane-hatch-partial"
    end
  end

  describe "sparkline" do
    test "renders a polyline with an emphasised last point" do
      html = render_component(&Viz.sparkline/1, points: [1, 5, 3], label: "CPU trend")
      assert html =~ "<polyline"
      assert html =~ "<circle"
      assert html =~ ~s(aria-label="CPU trend")
    end

    test "accepts Metrics.read-shaped maps" do
      html = render_component(&Viz.sparkline/1, points: [%{value: 1.0}, %{value: 2.0}])
      assert html =~ "<polyline"
    end

    test "absence renders the grey dash, never an empty svg" do
      for points <- [[], nil, [%{value: nil}]] do
        html = render_component(&Viz.sparkline/1, points: points, label: "CPU trend")
        refute html =~ "<svg"
        assert html =~ "no data"
      end
    end

    test "a flat series stays inside the viewbox" do
      html = render_component(&Viz.sparkline/1, points: [5, 5, 5])
      assert html =~ "<polyline"
      refute html =~ "NaN"
    end
  end

  describe "proportion_bar" do
    test "no threshold given: bar never tints, title has no threshold" do
      html = render_component(&Viz.proportion_bar/1, value: 95, label: "Capacity")
      assert html =~ "bg-primary"
      refute html =~ "bg-warning"
      refute html =~ "warn ≥"
    end

    test "threshold flips the colour AND is named (D-6 rule)" do
      html = render_component(&Viz.proportion_bar/1, value: 85, warn_at: 80, label: "Capacity")
      assert html =~ "bg-warning"
      assert html =~ "warn ≥ 80%"

      html = render_component(&Viz.proportion_bar/1, value: 97, warn_at: 80, crit_at: 95)
      assert html =~ "bg-error"
      assert html =~ "crit ≥ 95%"
    end

    test "nil value renders the absence form, not a zero-width bar" do
      html = render_component(&Viz.proportion_bar/1, value: nil, label: "Capacity")
      assert html =~ "no data"
      refute html =~ "width: "
    end

    test "values clamp into 0..100" do
      html = render_component(&Viz.proportion_bar/1, value: 250, max: 100)
      assert html =~ "width: 100.0%"
    end
  end
end
