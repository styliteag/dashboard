defmodule OrbitWeb.LogEventsLive do
  @moduledoc """
  Fleet log events — the aggregated critical syslog events across the caller's
  visible push instances, worst-first (lowest syslog severity, then highest
  count). Read from the DB (Orbit.Logs.Store), which the hub refreshes on each
  hourly logfile push. Scoped through the instance list (invariant 5); a slow
  300s tier timer (logs move at push cadence, not live).
  """

  use OrbitWeb, :live_view

  alias Orbit.Instances
  alias Orbit.Logs.Store

  @refresh_ms 300_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Process.send_after(self(), :refresh, @refresh_ms)
    {:ok, load(socket)}
  end

  @impl true
  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  defp load(socket) do
    rows =
      socket.assigns.current_user
      |> Instances.list_visible()
      |> Enum.filter(&Instances.Instance.agent_mode?/1)
      |> Enum.flat_map(fn inst ->
        for e <- Store.list_events(inst.id), do: %{instance: inst, event: e}
      end)
      |> Enum.sort_by(fn %{instance: i, event: e} -> {e.severity, -e.count, i.name} end)

    assign(socket, rows: rows)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:logs} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Log events <span class="ml-2 text-sm text-slate-500">({length(@rows)})</span>
        </h1>

        <div :if={@rows == []} class="text-sm text-slate-500">
          No critical log events in your scope.
        </div>

        <table :if={@rows != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">Sev</th>
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Program</th>
              <th class="py-2 pr-4 font-medium">Pattern</th>
              <th class="py-2 pr-4 text-right font-medium">Count</th>
              <th class="py-2 pr-4 font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={r <- @rows} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span class={["rounded px-1.5 py-0.5 text-xs", sev_class(r.event.severity)]}>
                  {sev_label(r.event.severity)}
                </span>
              </td>
              <td class="py-2 pr-4">
                <a
                  href={~p"/instances/#{r.instance.id}"}
                  class="text-slate-200 hover:text-emerald-300"
                >
                  {r.instance.name}
                </a>
              </td>
              <td class="py-2 pr-4 text-slate-400">{r.event.program}</td>
              <td class="py-2 pr-4 text-slate-300">{r.event.pattern}</td>
              <td class="py-2 pr-4 text-right text-slate-300">{r.event.count}</td>
              <td class="py-2 pr-4 text-slate-500">{r.event.last_ts}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  # Syslog severity: 0 emerg … 4 warning (lower = worse; nothing >4 is stored).
  defp sev_label(s) when s <= 2, do: "CRIT"
  defp sev_label(3), do: "ERR"
  defp sev_label(_), do: "WARN"

  defp sev_class(s) when s <= 2, do: "bg-red-900/60 text-red-300"
  defp sev_class(3), do: "bg-orange-900/50 text-orange-300"
  defp sev_class(_), do: "bg-amber-900/50 text-amber-300"
end
