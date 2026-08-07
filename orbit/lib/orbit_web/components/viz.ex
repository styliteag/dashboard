defmodule OrbitWeb.Components.Viz do
  @moduledoc """
  The shared data-viz vocabulary (docs/dataviz-language.md, DR-DV1): the
  timeline lane, the sparkline and the proportion bar. The RULES live in
  these components, not in a style guide (DR-DV2):

  - Absence renders the grey absence form, never a zero or an empty box.
  - A colour only flips when the component also names the threshold
    (`warn_at` + title) — the D-6 lesson, systemic.
  - Lanes carry hatch + dim + sr-only labels; axes exist only on
    `metric_chart` — sparklines and lanes are deliberately axis-free.

  Components never load data (DR-DV3) — they render what the page already
  holds.
  """

  use Phoenix.Component

  @doc """
  One state lane: absolute segments over a shared window. Colour + hatch
  (states survive greyscale, A-B2), resolved PROBLEM history dimmed so
  the outage still running at "now" keeps full chroma (D-15) — up
  segments never dim: dimming them split a lane's green into two shades
  around every past blip, which read as a third state (prod feedback
  2026-08-07). Per-segment `title` + sr-only text when a `:label` is
  present.

  Segments: `%{state: :up | :partial | :down | other, left: number,
  width: number, label: binary | nil}` (left/width in percent).
  """
  attr :segments, :list, required: true
  attr :height, :string, default: "h-3.5"
  attr :dim_resolved, :boolean, default: true, doc: "false for single-window dialogs"
  attr :rest, :global

  def timeline_lane(assigns) do
    ~H"""
    <div class={["relative flex-1 overflow-hidden rounded bg-base-300", @height]} {@rest}>
      <div
        :for={seg <- @segments}
        class={[
          "absolute h-full",
          lane_color(seg.state),
          @dim_resolved && seg.state != :up && seg.left + seg.width < 99.9 && "opacity-60"
        ]}
        style={"left: #{Float.round(seg.left / 1, 2)}%; width: #{Float.round(seg.width / 1, 2)}%"}
        title={seg[:label]}
      >
        <span :if={seg[:label]} class="sr-only">{seg.label}</span>
      </div>
    </div>
    """
  end

  @doc "Lane state → colour + hatch classes. The single palette for every lane surface."
  def lane_color(:up), do: "bg-primary"
  def lane_color(:partial), do: "bg-warning lane-hatch-partial"
  def lane_color(:down), do: "bg-error lane-hatch-down"
  def lane_color(_unknown), do: "bg-neutral"

  @doc """
  The four-state lane legend (availability-page original): names the
  states — a bare coloured block explains nothing (U-Q2) — and shows
  their hatches.
  """
  def lane_legend(assigns) do
    ~H"""
    <div class="mb-2 flex flex-wrap items-center gap-3 text-[10px] text-base-content/70">
      <span><span class="mr-1 inline-block h-2.5 w-4 rounded-sm bg-primary"></span>up</span>
      <span>
        <span class="mr-1 inline-block h-2.5 w-4 rounded-sm bg-warning lane-hatch-partial"></span>
        partial
      </span>
      <span>
        <span class="mr-1 inline-block h-2.5 w-4 rounded-sm bg-error lane-hatch-down"></span> down
      </span>
      <span>
        <span class="mr-1 inline-block h-2.5 w-4 rounded-sm bg-neutral"></span>no data
      </span>
      <span class="ml-auto">resolved history is dimmed; full colour = still current</span>
    </div>
    """
  end

  @doc """
  Axis-free mini trend, ~24px tall, from points the page already loaded
  (`[%{value: number}]` like `Orbit.Metrics.read/3`, or bare numbers).
  The last point is emphasised; empty/nil renders the grey absence dash
  with an sr-only "no data" — never an empty box.
  """
  attr :points, :list, default: []
  attr :class, :any, default: "text-primary", doc: "stroke colour class (theme token)"
  attr :label, :string, default: nil, doc: "accessible name, e.g. \"CPU trend\""

  def sparkline(assigns) do
    values =
      assigns.points
      |> List.wrap()
      |> Enum.map(fn
        %{value: v} when is_number(v) -> v * 1.0
        v when is_number(v) -> v * 1.0
        _ -> nil
      end)
      |> Enum.reject(&is_nil/1)

    {svg_points, last_xy} = spark_geometry(values)
    assigns = assign(assigns, values: values, svg_points: svg_points, last_xy: last_xy)

    ~H"""
    <span :if={@values == []} class="inline-block h-6 w-20 align-middle" aria-label={@label}>
      <span class="block h-px w-full translate-y-3 border-t border-dashed border-base-content/30"></span>
      <span class="sr-only">no data</span>
    </span>
    <svg
      :if={@values != []}
      viewBox="0 0 100 24"
      preserveAspectRatio="none"
      class={["inline-block h-6 w-20 align-middle", @class]}
      role="img"
      aria-label={@label || "trend"}
    >
      <polyline
        points={@svg_points}
        fill="none"
        stroke="currentColor"
        stroke-width="1.5"
        vector-effect="non-scaling-stroke"
      />
      <circle cx={elem(@last_xy, 0)} cy={elem(@last_xy, 1)} r="2" fill="currentColor" />
    </svg>
    """
  end

  # x spread over 0..100; y normalised into 2..22 (padding), flat series
  # centred. A single point renders as a short dash ending at that value.
  defp spark_geometry([]), do: {"", {0, 0}}
  defp spark_geometry([v]), do: spark_geometry([v, v])

  defp spark_geometry(values) do
    {min, max} = Enum.min_max(values)
    span = if max == min, do: 1.0, else: max - min
    n = length(values)

    coords =
      values
      |> Enum.with_index()
      |> Enum.map(fn {v, i} ->
        {Float.round(i * 100.0 / (n - 1), 2), Float.round(22.0 - (v - min) / span * 20.0, 2)}
      end)

    {Enum.map_join(coords, " ", fn {x, y} -> "#{x},#{y}" end), List.last(coords)}
  end

  @doc """
  Capacity/usage bar. The colour only flips when `warn_at` is given, and
  then the threshold is named in the title (DR-DV2 / the D-6 lesson: an
  amber gauge without its threshold is unreadable). nil value renders
  the absence form.
  """
  attr :value, :any, required: true, doc: "number or nil (absence)"
  attr :max, :any, default: 100
  attr :warn_at, :any, default: nil, doc: "percent 0..100 at which the bar tints warning"
  attr :crit_at, :any, default: nil, doc: "percent at which the bar tints error"
  attr :label, :string, default: nil, doc: "what is measured, for the title/sr text"

  def proportion_bar(assigns) do
    pct = bar_pct(assigns.value, assigns.max)
    assigns = assign(assigns, pct: pct, title: bar_title(assigns, pct))

    ~H"""
    <span
      class="inline-block h-1.5 w-full overflow-hidden rounded-full bg-base-300 align-middle"
      title={@title}
    >
      <span :if={is_nil(@pct)} class="sr-only">{@label || "value"}: no data</span>
      <span
        :if={@pct}
        class={["block h-full rounded-full", bar_tint(@pct, @warn_at, @crit_at)]}
        style={"width: #{@pct}%"}
      >
        <span class="sr-only">{@title}</span>
      </span>
    </span>
    """
  end

  defp bar_pct(value, max) when is_number(value) and is_number(max) and max > 0,
    do: value |> Kernel./(max) |> Kernel.*(100.0) |> min(100.0) |> max(0.0) |> Float.round(1)

  defp bar_pct(_value, _max), do: nil

  defp bar_tint(pct, _warn, crit) when is_number(crit) and pct >= crit, do: "bg-error"
  defp bar_tint(pct, warn, _crit) when is_number(warn) and pct >= warn, do: "bg-warning"
  defp bar_tint(_pct, _warn, _crit), do: "bg-primary"

  defp bar_title(assigns, pct) do
    base = [assigns.label, pct && "#{pct}%"] |> Enum.reject(&is_nil/1) |> Enum.join(": ")

    thresholds =
      [
        assigns.warn_at && "warn ≥ #{assigns.warn_at}%",
        assigns.crit_at && "crit ≥ #{assigns.crit_at}%"
      ]
      |> Enum.reject(&is_nil/1)

    case {base, thresholds} do
      {"", []} -> nil
      {b, []} -> b
      {"", t} -> Enum.join(t, ", ")
      {b, t} -> "#{b} (#{Enum.join(t, ", ")})"
    end
  end
end
