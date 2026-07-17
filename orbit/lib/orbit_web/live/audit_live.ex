defmodule OrbitWeb.AuditLive do
  @moduledoc """
  Audit surface with two tabs (DR-AL9 — no extra nav entry):

  - **Actions** — the mutation trail (audit_log rows, colour-coded result).
  - **Access** — who uses the dashboard (DR-AL7): summary aggregates
    (online sessions, logins 24h, blocks by reason, busiest principals)
    over the merged chronological timeline (auth events, instance
    accesses, geoip/crowdsec denials, sampled requests). Request samples
    default OFF in the filter (polling noise).

  Gate is on_mount(:require_admin_or_superadmin) — DR-AL1: the superadmin's
  role is view_only, plain require_admin would lock them out of exactly
  their oversight domain. Refreshes on the 30s standard tier.
  """

  use OrbitWeb, :live_view

  alias Orbit.Access

  @limit 100
  @refresh_ms 30_000

  @timeline_types [
    {:auth, "Logins"},
    {:access, "Instance access"},
    {:denial, "Blocked"},
    {:request, "Requests"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Process.send_after(self(), :refresh, @refresh_ms)

    socket =
      socket
      |> assign(tab: :actions, types: MapSet.new([:auth, :access, :denial]))
      |> load()

    {:ok, socket}
  end

  @impl true
  def handle_event("tab", %{"tab" => tab}, socket) when tab in ["actions", "access"] do
    {:noreply, socket |> assign(tab: String.to_existing_atom(tab)) |> load()}
  end

  def handle_event("toggle_type", %{"type" => type}, socket) do
    type = String.to_existing_atom(type)
    types = socket.assigns.types

    types =
      if MapSet.member?(types, type),
        do: MapSet.delete(types, type),
        else: MapSet.put(types, type)

    {:noreply, socket |> assign(types: types) |> load()}
  end

  def handle_event("refresh", _params, socket) do
    {:noreply, load(socket)}
  end

  @impl true
  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  defp load(%{assigns: %{tab: :access}} = socket) do
    assign(socket,
      summary: Access.summary(),
      timeline: Access.timeline(MapSet.to_list(socket.assigns.types), @limit)
    )
  end

  defp load(socket) do
    assign(socket, rows: load_rows())
  end

  defp load_rows do
    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT ts, action, result, user_id, target_type, target_id, source_ip " <>
          "FROM audit_log ORDER BY id DESC LIMIT #{@limit}"
      )

    for [ts, action, result, user_id, ttype, tid, ip] <- rows do
      %{
        ts: ts,
        action: action,
        result: result,
        user_id: user_id,
        target: target(ttype, tid),
        ip: ip
      }
    end
  end

  defp target(nil, _), do: "—"
  defp target(t, nil), do: t
  defp target(t, id), do: "#{t}:#{id}"

  @impl true
  def render(assigns) do
    assigns = Phoenix.Component.assign(assigns, :timeline_types, @timeline_types)

    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:audit} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">Audit</h1>
          <div class="flex rounded border border-slate-800 text-xs">
            <button
              :for={{tab, label} <- [{:actions, "Actions"}, {:access, "Access"}]}
              phx-click="tab"
              phx-value-tab={tab}
              class={[
                "px-3 py-1",
                @tab == tab && "bg-slate-800 text-slate-100",
                @tab != tab && "text-slate-400 hover:text-slate-200"
              ]}
            >
              {label}
            </button>
          </div>
          <button
            phx-click="refresh"
            class="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>

        <div :if={@tab == :actions}>
          <table class="w-full text-left text-sm">
            <thead class="text-slate-500">
              <tr class="border-b border-slate-800">
                <th class="py-2 pr-4 font-medium">Time (UTC)</th>
                <th class="py-2 pr-4 font-medium">Action</th>
                <th class="py-2 pr-4 font-medium">Result</th>
                <th class="py-2 pr-4 font-medium">User</th>
                <th class="py-2 pr-4 font-medium">Target</th>
                <th class="py-2 pr-4 font-medium">IP</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={r <- @rows} class="border-b border-slate-800/50">
                <td class="py-2 pr-4 font-mono text-xs text-slate-500">{fmt_ts(r.ts)}</td>
                <td class="py-2 pr-4 text-slate-300">{r.action}</td>
                <td class="py-2 pr-4">
                  <span class={["rounded px-1.5 py-0.5 text-xs", result_class(r.result)]}>
                    {r.result}
                  </span>
                </td>
                <td class="py-2 pr-4 text-slate-400">{r.user_id || "—"}</td>
                <td class="py-2 pr-4 text-slate-400">{r.target}</td>
                <td class="py-2 pr-4 text-slate-500">{r.ip || "—"}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div :if={@tab == :access}>
          <div class="mb-6 grid gap-4 md:grid-cols-4">
            <div class="rounded-lg border border-slate-800 bg-slate-900 p-4">
              <div class="text-xs text-slate-500">Online now</div>
              <div class="mt-1 text-2xl text-emerald-300">{length(@summary.online)}</div>
              <div :for={s <- Enum.take(@summary.online, 5)} class="mt-1 text-xs text-slate-400">
                {s.username || "user ##{s.user_id}"} · {s.ip}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900 p-4">
              <div class="text-xs text-slate-500">Logins (24h)</div>
              <div class="mt-1 text-2xl text-slate-200">
                {@summary.logins_24h.ok}
                <span :if={@summary.logins_24h.failed > 0} class="text-base text-red-400">
                  / {@summary.logins_24h.failed} failed
                </span>
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900 p-4">
              <div class="text-xs text-slate-500">Blocked (all time)</div>
              <div class="mt-1 text-2xl text-red-300">
                {@summary.blocks |> Enum.map(& &1.count) |> Enum.sum()}
              </div>
              <div :for={b <- Enum.take(@summary.blocks, 4)} class="mt-1 text-xs text-slate-400">
                {b.reason} · {b.count}
              </div>
            </div>
            <div class="rounded-lg border border-slate-800 bg-slate-900 p-4">
              <div class="text-xs text-slate-500">Requests (24h)</div>
              <div :for={p <- Enum.take(@summary.principals_24h, 5)} class="mt-1 text-xs">
                <span class="text-slate-300">{p.principal}</span>
                <span class="text-slate-500"> · {p.count}</span>
              </div>
            </div>
          </div>

          <div class="mb-3 flex items-center gap-2 text-xs">
            <span class="text-slate-500">Show:</span>
            <button
              :for={{type, label} <- @timeline_types}
              phx-click="toggle_type"
              phx-value-type={type}
              class={[
                "rounded border px-2 py-0.5",
                MapSet.member?(@types, type) && "border-emerald-700 text-emerald-300",
                !MapSet.member?(@types, type) && "border-slate-700 text-slate-500"
              ]}
            >
              {label}
            </button>
          </div>

          <table class="w-full text-left text-sm">
            <thead class="text-slate-500">
              <tr class="border-b border-slate-800">
                <th class="py-2 pr-4 font-medium">Time (UTC)</th>
                <th class="py-2 pr-4 font-medium">Type</th>
                <th class="py-2 pr-4 font-medium">Who</th>
                <th class="py-2 pr-4 font-medium">IP</th>
                <th class="py-2 pr-4 font-medium">Event</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={e <- @timeline} class="border-b border-slate-800/50">
                <td class="py-2 pr-4 font-mono text-xs text-slate-500">{fmt_ts(e.ts)}</td>
                <td class="py-2 pr-4">
                  <span class={["rounded px-1.5 py-0.5 text-xs", type_class(e.type)]}>
                    {type_label(e.type)}
                  </span>
                </td>
                <td class="py-2 pr-4 text-slate-300">{e.who}</td>
                <td class="py-2 pr-4 text-slate-500">{e.ip || "—"}</td>
                <td class="py-2 pr-4 text-slate-400">{e.text}</td>
              </tr>
            </tbody>
          </table>
          <div :if={@timeline == []} class="py-4 text-sm text-slate-500">
            No events for the selected types.
          </div>
        </div>
      </section>
    </main>
    """
  end

  defp fmt_ts(%NaiveDateTime{} = ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  defp fmt_ts(%DateTime{} = ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  defp fmt_ts(other), do: to_string(other)

  defp result_class("ok"), do: "bg-emerald-900/50 text-emerald-300"
  defp result_class("pending"), do: "bg-slate-700 text-slate-300"
  defp result_class("denied"), do: "bg-red-900/60 text-red-300"
  defp result_class(_), do: "bg-amber-900/50 text-amber-300"

  defp type_label(:login_ok), do: "LOGIN"
  defp type_label(:login_fail), do: "LOGIN FAIL"
  defp type_label(:logout), do: "LOGOUT"
  defp type_label(:session_expired), do: "EXPIRED"
  defp type_label(:denial), do: "BLOCKED"
  defp type_label(:access), do: "ACCESS"
  defp type_label(:request), do: "REQ"

  defp type_class(:login_ok), do: "bg-emerald-900/50 text-emerald-300"
  defp type_class(:login_fail), do: "bg-red-900/60 text-red-300"
  defp type_class(:denial), do: "bg-red-900/60 text-red-300"
  defp type_class(:access), do: "bg-sky-900/50 text-sky-300"
  defp type_class(:request), do: "bg-slate-700 text-slate-400"
  defp type_class(_), do: "bg-amber-900/50 text-amber-300"
end
