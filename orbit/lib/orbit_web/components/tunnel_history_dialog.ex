defmodule OrbitWeb.Components.TunnelHistoryDialog do
  @moduledoc """
  Tunnel history / graph dialog — the up-down timeline over the recorded
  transition log plus, in history mode, the transition table itself.

  Lived inline in VpnLive, which meant the per-instance IPsec tab (where an
  operator lands when ONE tunnel is misbehaving) had no way into the
  timeline at all: they had to go back out to the fleet page and find the
  row again. Extracted verbatim so both surfaces render the identical
  dialog from the same `history` assign.

  Read-only. The caller re-scopes the instance before building the assign
  (both do), so nothing here trusts an id.
  """

  use Phoenix.Component

  attr :history, :map, default: nil, doc: "nil = closed; see VpnLive.history_open/2"

  def tunnel_history_dialog(assigns) do
    ~H"""
    <%!-- Tunnel history dialog: up/down timeline + recorded transitions. --%>
    <div
      :if={@history}
      class="fixed inset-0 z-50 flex items-center justify-center bg-base-100/80 p-4"
    >
      <div class="max-h-[80vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-base-content/20 bg-base-200 p-5">
        <div class="flex items-center justify-between">
          <h3 class="text-sm font-medium text-base-content">
            {if @history.mode == :graph, do: "Tunnel graph", else: "Tunnel history"} — {@history.label}
            <span class="ml-1 text-xs text-base-content/60">{@history.instance_name}</span>
          </h3>
          <button
            phx-click="history_close"
            class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
          >
            Close
          </button>
        </div>

        <%!-- Window selector. Without it the graph spanned "oldest recorded
             event → now", so two tunnels drew the same picture at wildly
             different scales and neither said over what period. --%>
        <div class="mt-3 flex items-center gap-1">
          <span class="mr-1 text-[10px] text-base-content/50">Window</span>
          <button
            :for={{key, label} <- [{"24h", "24h"}, {"7d", "7d"}, {"30d", "30d"}, {"all", "all"}]}
            phx-click="history_window"
            phx-value-window={key}
            class={[
              "rounded px-2 py-0.5 text-[10px]",
              if(@history.window == key,
                do: "bg-base-300 text-base-content",
                else: "text-base-content/60 hover:bg-base-300/60"
              )
            ]}
          >
            {label}
          </button>
        </div>

        <%!-- Three state lanes from the transition log (TunnelGraphDialog
             parity): green up, red down, amber partial, grey no data. --%>
        <% lanes =
          Orbit.Ipsec.History.lanes(
            @history.events,
            %{
              up: @history.up,
              phase2_up: @history.phase2_up,
              phase2_total: @history.phase2_total
            },
            DateTime.utc_now(),
            @history.window_start
          ) %>
        <div class="mt-4 space-y-2">
          <div
            :for={
              {label, segs} <- [
                {"Phase 1", lanes.phase1},
                {"Phase 2", lanes.phase2},
                {"Ping", lanes.ping}
              ]
            }
            class="flex items-center gap-2"
          >
            <span class="w-16 text-right text-[10px] text-base-content/60">{label}</span>
            <div class={[
              "relative flex-1 overflow-hidden rounded bg-base-300",
              if(@history.mode == :graph, do: "h-7", else: "h-3.5")
            ]}>
              <div
                :for={seg <- segs}
                class={["absolute h-full", lane_color(seg.state)]}
                style={"left: #{Float.round(seg.left, 2)}%; width: #{Float.round(seg.width, 2)}%"}
              >
              </div>
            </div>
          </div>
          <%!-- Phase 2 in numbers. "partial" on the colour lane looks the
               same whether one of two child SAs dropped or one of eight, and
               that is always the next question. --%>
          <div class="flex items-center gap-2">
            <span class="w-16 text-right text-[10px] text-base-content/60">P2 count</span>
            <div class="relative h-4 flex-1 overflow-hidden rounded bg-base-300/50">
              <div
                :for={
                  seg <-
                    Orbit.Ipsec.History.phase2_numeric(
                      @history.events,
                      %{phase2_up: @history.phase2_up, phase2_total: @history.phase2_total},
                      DateTime.utc_now(),
                      @history.window_start
                    )
                }
                title={seg.label}
                class="absolute flex h-full items-center justify-center overflow-hidden border-r border-base-100/40 text-[9px] text-base-content/70"
                style={"left: #{Float.round(seg.left, 2)}%; width: #{Float.round(seg.width, 2)}%"}
              >
                {seg.label}
              </div>
            </div>
          </div>
          <div class="flex justify-between pl-[4.5rem] text-[10px] text-base-content/40">
            <span :if={@history.events != []}>{fmt_event_ts(lanes.window_start)}</span>
            <span :if={@history.events == []}>no recorded transitions yet</span>
            <span>now</span>
          </div>
          <div class="flex gap-3 pl-[4.5rem] text-[10px] text-base-content/60">
            <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-primary"></span>up</span>
            <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-warning"></span>partial</span>
            <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-error"></span>down</span>
            <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-neutral"></span>no data</span>
          </div>
        </div>

        <table
          :if={@history.mode == :history and @history.events != []}
          class="mt-4 w-full text-left text-xs"
        >
          <thead class="text-base-content/60">
            <tr class="border-b border-base-300">
              <th class="py-1 pr-3 font-medium">Time (UTC)</th>
              <th class="py-1 pr-3 font-medium">Event</th>
              <th class="py-1 pr-3 font-medium">Phase 2</th>
              <th class="py-1 font-medium">Change</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={e <- @history.events} class="border-b border-base-300/50 last:border-0">
              <td class="py-1 pr-3 font-mono text-base-content/60">{fmt_event_ts(e.ts)}</td>
              <td class={["py-1 pr-3", event_color(e.event_type)]}>{e.event_type}</td>
              <td class="py-1 pr-3 text-base-content/60">{e.child_name}</td>
              <td class="py-1 text-base-content/70">{e.old_value} → {e.new_value}</td>
            </tr>
          </tbody>
        </table>
        <p
          :if={@history.mode == :history and @history.events == []}
          class="mt-4 text-sm text-base-content/60"
        >
          No transitions recorded yet — events appear as soon as the tunnel
          changes state (orbit records them per agent push).
        </p>
      </div>
    </div>
    """
  end

  def lane_color(:up), do: "bg-primary"
  def lane_color(:partial), do: "bg-warning"
  def lane_color(:down), do: "bg-error"
  def lane_color(:unknown), do: "bg-neutral"

  def event_color("phase1_up"), do: "text-primary"
  def event_color("ping_ok"), do: "text-primary"
  def event_color("phase1_down"), do: "text-error"
  def event_color("ping_fail"), do: "text-error"
  def event_color(_), do: "text-warning"

  def fmt_event_ts(ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S UTC")
end
