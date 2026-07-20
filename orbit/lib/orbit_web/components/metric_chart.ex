defmodule OrbitWeb.Components.MetricChart do
  @moduledoc """
  Server-rendered SVG area chart for one metric time-series
  (InstanceDetailPage MetricChart parity). Deliberately no JS chart lib —
  the series is small (≤ ~720 bucketed points), LiveView re-renders it on
  the metrics timer, and a vendored uPlot hook was judged not worth the
  payload (open decision §8 of the rewrite plan, resolved here as SVG).

  X is index-based like the recharts original (categorical axis), so gaps
  in the series compress instead of leaving holes. Hover readouts come from
  native `<title>` tooltips on invisible sample dots, downsampled to ≤60 so
  a raw 1h series doesn't blow up the DOM.
  """

  use Phoenix.Component

  attr :label, :string, required: true
  attr :points, :list, required: true, doc: "[%{ts: DateTime, value: float}] oldest first"
  attr :color, :string, default: "#10b981"
  # :auto = scale to the data max (nice-rounded); a number pins the domain (0..max).
  attr :domain_max, :any, default: 100
  attr :scale, :any, default: 1, doc: "divide raw values before plotting (ms → s etc.)"
  attr :ref_y, :any, default: nil, doc: "dashed WARN reference line, in plotted units"
  attr :unit, :string, default: ""

  def metric_chart(assigns) do
    values = for p <- assigns.points, do: p.value / assigns.scale
    ymax = y_max(values, assigns.domain_max, assigns.ref_y)
    line = line_points(values, ymax)

    assigns =
      assign(assigns,
        values: values,
        ymax: ymax,
        line: line,
        area: (line && "0,40 #{line} 100,40") || nil,
        ref_line_y: assigns.ref_y && 40.0 - assigns.ref_y / ymax * 40.0,
        grad_id: "grad-" <> String.replace(assigns.label, ~r/[^A-Za-z0-9]+/, "-"),
        dots: hover_dots(assigns.points, values, ymax)
      )

    ~H"""
    <%!-- No phx-update="ignore": the metrics timer re-renders this chart and
         the hook's updated/0 re-reads the new sample dots. --%>
    <div
      id={"chart-#{@grad_id}"}
      phx-hook="ChartHover"
      class="rounded-xl border border-base-300 bg-base-200/60 p-4"
    >
      <div class="mb-3 flex items-baseline justify-between gap-3">
        <h3 class="text-xs text-base-content/60">{@label}</h3>
        <%!-- Readout is filled by the ChartHover hook on pointer move and
             cleared on leave; the last value stays visible when idle. --%>
        <span data-readout class="truncate text-xs text-base-content/70"></span>
        <span :if={@values != []} class="shrink-0 text-xs text-base-content/70">
          {fmt_val(List.last(@values))}{@unit}
        </span>
      </div>
      <p :if={@line == nil} class="py-8 text-center text-sm text-base-content/40">
        No data for this range.
      </p>
      <div :if={@line != nil}>
        <svg viewBox="0 0 100 40" preserveAspectRatio="none" class="h-40 w-full text-base-content">
          <defs>
            <linearGradient id={@grad_id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stop-color={@color} stop-opacity="0.3" />
              <stop offset="95%" stop-color={@color} stop-opacity="0" />
            </linearGradient>
          </defs>
          <%!-- Gridlines follow the theme via currentColor — a hardcoded
               slate hex read near-black on the light designs. --%>
          <line
            :for={y <- [10, 20, 30]}
            x1="0"
            y1={y}
            x2="100"
            y2={y}
            stroke="currentColor"
            stroke-opacity="0.12"
            stroke-width="0.3"
            stroke-dasharray="1.5 1.5"
          />
          <polygon points={@area} fill={"url(##{@grad_id})"} />
          <polyline
            points={@line}
            fill="none"
            stroke={@color}
            stroke-width="0.6"
            vector-effect="non-scaling-stroke"
          />
          <line
            :if={@ref_line_y}
            x1="0"
            y1={@ref_line_y}
            x2="100"
            y2={@ref_line_y}
            stroke="#f59e0b"
            stroke-width="0.4"
            stroke-dasharray="2 2"
            stroke-opacity="0.7"
            vector-effect="non-scaling-stroke"
          />
          <line
            data-crosshair
            x1="0"
            y1="0"
            x2="0"
            y2="40"
            stroke="currentColor"
            stroke-opacity="0.45"
            stroke-width="0.4"
            vector-effect="non-scaling-stroke"
            style="opacity:0"
          />
          <circle :for={d <- @dots} cx={d.x} cy={d.y} r="1.6" fill="transparent">
            <title>{d.title}</title>
          </circle>
        </svg>
        <div class="mt-1 flex justify-between text-[10px] text-base-content/40">
          <span>{fmt_ts(List.first(@points))}</span>
          <span class="text-base-content/60">0–{fmt_val(@ymax)}{@unit}</span>
          <span>{fmt_ts(List.last(@points))}</span>
        </div>
      </div>
    </div>
    """
  end

  # ---- geometry ------------------------------------------------------------

  defp y_max([], _domain, _ref), do: 1.0

  defp y_max(values, :auto, ref) do
    nice(Enum.max([Enum.max(values), ref || 0.0, 0.000001]))
  end

  defp y_max(_values, max, _ref) when is_number(max), do: max * 1.0

  # Round up to 1/2/5 × 10^k so the axis cap reads clean.
  defp nice(v) do
    exp = :math.pow(10, Float.floor(:math.log10(v)))
    frac = v / exp

    mult =
      cond do
        frac <= 1.0 -> 1.0
        frac <= 2.0 -> 2.0
        frac <= 5.0 -> 5.0
        true -> 10.0
      end

    mult * exp
  end

  defp line_points([], _ymax), do: nil

  defp line_points([only], ymax), do: "0,#{y_of(only, ymax)} 100,#{y_of(only, ymax)}"

  defp line_points(values, ymax) do
    n = length(values)

    values
    |> Enum.with_index()
    |> Enum.map_join(" ", fn {v, i} -> "#{x_of(i, n)},#{y_of(v, ymax)}" end)
  end

  defp x_of(i, n), do: Float.round(i / (n - 1) * 100.0, 2)

  defp y_of(v, ymax) do
    40.0 - min(max(v / ymax, 0.0), 1.0) * 40.0
  end

  # ≤60 invisible hover targets with native title tooltips.
  defp hover_dots(points, values, ymax) do
    n = length(values)
    step = max(div(n, 60), 1)

    points
    |> Enum.zip(values)
    |> Enum.with_index()
    |> Enum.filter(fn {_pv, i} -> rem(i, step) == 0 or i == n - 1 end)
    |> Enum.map(fn {{p, v}, i} ->
      %{
        x: x_of(i, max(n, 2)),
        y: y_of(v, ymax),
        title: "#{Calendar.strftime(p.ts, "%m-%d %H:%M")} — #{fmt_val(v)}"
      }
    end)
  end

  # ---- labels ---------------------------------------------------------------

  defp fmt_ts(nil), do: ""
  defp fmt_ts(%{ts: ts}), do: Calendar.strftime(ts, "%m-%d %H:%M")

  defp fmt_val(v) when is_float(v) do
    if v == Float.round(v), do: trunc(v), else: Float.round(v, 1)
  end

  defp fmt_val(v), do: v
end
