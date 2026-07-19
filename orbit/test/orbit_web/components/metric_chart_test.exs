defmodule OrbitWeb.Components.MetricChartTest do
  @moduledoc "SVG metric chart: empty state, scaling, pinned vs auto domain, WARN line."
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias OrbitWeb.Components.MetricChart

  defp pts(values) do
    t0 = ~U[2026-07-18 10:00:00Z]

    values
    |> Enum.with_index()
    |> Enum.map(fn {v, i} -> %{ts: DateTime.add(t0, i * 60), value: v * 1.0} end)
  end

  test "empty series renders the no-data state, no svg" do
    html = render_component(&MetricChart.metric_chart/1, label: "CPU %", points: [])
    assert html =~ "No data for this range."
    refute html =~ "<svg"
  end

  test "percent series plots against the pinned 0..100 domain" do
    html =
      render_component(&MetricChart.metric_chart/1, label: "CPU %", points: pts([0, 50, 100]))

    # 0% sits on the floor (y=40), 50% mid (y=20), 100% on the ceiling (y=0).
    assert html =~ "0,40.0 50.0,20.0 100.0,0.0"
    assert html =~ "0–100"
  end

  test "scale divides raw values and the WARN reference line lands in domain units" do
    html =
      render_component(&MetricChart.metric_chart/1,
        label: "Agent collect (s)",
        points: pts([2_000, 4_000]),
        domain_max: :auto,
        scale: 1000,
        ref_y: 10,
        unit: "s"
      )

    # ymax = nice(max(4s, ref 10s)) = 10s → ref line at the top (y=0).
    assert html =~ "0–10s"
    assert html =~ ~s(stroke="#f59e0b")
  end

  test "auto domain nice-rounds the data max" do
    html =
      render_component(&MetricChart.metric_chart/1,
        label: "Load (1m)",
        points: pts([3]),
        domain_max: :auto
      )

    assert html =~ "0–5"
  end

  test "hover dots carry native title tooltips" do
    html = render_component(&MetricChart.metric_chart/1, label: "RAM %", points: pts([10, 20]))
    assert html =~ "<title>"
    assert html =~ "07-18 10:01"
  end
end
