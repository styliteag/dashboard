defmodule OrbitWeb.Components.CheckHistoryDialog do
  @moduledoc """
  State timeline of one check — the connectivity-monitor counterpart to
  `TunnelHistoryDialog`.

  A monitor's row shows what it is doing right now. "Has this link been
  flapping all week, or did it just drop?" needed the recorded transitions,
  which orbit has been writing all along with nothing reading them per
  monitor. Same shape as the tunnel dialog so the two feel like one feature:
  a lane above, the transition table below.

  Read-only. The caller re-scopes the instance before building the assign.

  One thing the timeline shows honestly rather than hides: connectivity
  checks are flap-debounced (three consecutive failing pushes before CRIT,
  instant recovery), so a recorded outage starts a few pushes after the real
  one. That is the alerting behaviour, not a gap in the record.
  """

  use Phoenix.Component

  alias Orbit.Checks.History

  attr :history, :map, default: nil, doc: "nil = closed; see ConnectivityLive.history_open/2"

  def check_history_dialog(assigns) do
    ~H"""
    <div
      :if={@history}
      class="fixed inset-0 z-50 flex items-center justify-center bg-base-100/80 p-4"
    >
      <div class="max-h-[80vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-base-content/20 bg-base-200 p-5">
        <div class="flex items-center justify-between">
          <h3 class="text-sm font-medium text-base-content">
            Monitor history — {@history.label}
            <span class="ml-1 text-xs text-base-content/60">{@history.instance_name}</span>
          </h3>
          <button
            phx-click="check_history_close"
            class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
          >
            Close
          </button>
        </div>

        <% lane = History.lane(@history.events, @history.live_state, DateTime.utc_now()) %>
        <div class="mt-4 space-y-2">
          <div class="flex items-center gap-2">
            <span class="w-16 text-right text-[10px] text-base-content/60">State</span>
            <div class="relative h-7 flex-1 overflow-hidden rounded bg-base-300">
              <div
                :for={seg <- lane.segments}
                class={["absolute h-full", lane_color(seg.state)]}
                style={"left: #{Float.round(seg.left, 2)}%; width: #{Float.round(seg.width, 2)}%"}
              >
              </div>
            </div>
          </div>
          <div class="flex justify-between pl-[4.5rem] text-[10px] text-base-content/40">
            <span :if={@history.events != []}>{fmt_ts(lane.window_start)}</span>
            <span :if={@history.events == []}>no recorded transitions yet</span>
            <span>now</span>
          </div>
          <div class="flex gap-3 pl-[4.5rem] text-[10px] text-base-content/60">
            <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-primary"></span>OK</span>
            <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-warning"></span>WARN</span>
            <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-error"></span>CRIT</span>
            <span>
              <span class="mr-1 inline-block h-2 w-2 rounded-sm bg-neutral"></span>unknown
            </span>
          </div>
        </div>

        <table :if={@history.events != []} class="mt-4 w-full text-left text-xs">
          <thead class="text-base-content/60">
            <tr class="border-b border-base-300">
              <th class="py-1 pr-3 font-medium">Time (UTC)</th>
              <th class="py-1 pr-3 font-medium">Change</th>
              <th class="py-1 font-medium">Summary</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={e <- @history.events} class="border-b border-base-300/50 last:border-0">
              <td class="py-1 pr-3 font-mono text-base-content/60">{fmt_ts(e.ts)}</td>
              <td class={["py-1 pr-3", state_color(e.new_state)]}>
                {History.state_label(e.old_state)} → {History.state_label(e.new_state)}
              </td>
              <td class="py-1 text-base-content/70">{e.summary}</td>
            </tr>
          </tbody>
        </table>
        <p :if={@history.events == []} class="mt-4 text-sm text-base-content/60">
          No transitions recorded yet — a row appears the moment the monitor changes
          state. Failures are debounced over three polls, so a short blip may leave
          no trace at all.
        </p>
      </div>
    </div>
    """
  end

  defp lane_color(:up), do: "bg-primary"
  defp lane_color(:partial), do: "bg-warning"
  defp lane_color(:down), do: "bg-error"
  defp lane_color(_), do: "bg-neutral"

  defp state_color(0), do: "text-primary"
  defp state_color(1), do: "text-warning"
  defp state_color(2), do: "text-error"
  defp state_color(_), do: "text-base-content/60"

  defp fmt_ts(ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S UTC")
end
