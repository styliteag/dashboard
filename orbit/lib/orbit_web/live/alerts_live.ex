defmodule OrbitWeb.AlertsLive do
  @moduledoc """
  Fleet alerts — every non-OK evaluated check across the caller's visible
  instances, worst-first. Runs the full evaluate→overlay chain (Orbit.Checks
  .Export.evaluated) so it shows exactly what the Checkmk/Prometheus exports
  and the per-instance view show (the four-surface parity rule). Scoped
  through the instance list (invariant 5). Refreshes on hub roster edges +
  a 30s tier timer.
  """

  use OrbitWeb, :live_view

  alias Orbit.Checks.Export
  alias Orbit.Checks.ServiceCheck
  alias Orbit.Hub

  @refresh_ms 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
      Process.send_after(self(), :refresh, @refresh_ms)
    end

    {:ok, load(socket)}
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  defp load(socket) do
    alerts =
      socket.assigns.current_user
      |> Export.evaluated(DateTime.utc_now())
      |> Enum.flat_map(fn {inst, checks} ->
        for c <- checks, c.state != 0, do: %{inst: inst, check: c}
      end)
      # Worst-first: CRIT > WARN > UNKNOWN, then by instance/key for stability.
      |> Enum.sort_by(fn %{inst: i, check: c} ->
        {-ServiceCheck.severity(c.state), i.name, c.key}
      end)

    assign(socket, alerts: alerts)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <header class="flex items-center justify-between border-b border-slate-800 bg-slate-900 px-6 py-3">
        <div class="flex items-center gap-3">
          <a href={~p"/"} class="font-semibold text-slate-100">STYLiTE Orbit</a>
          <nav class="flex gap-3 text-sm text-slate-400">
            <a href={~p"/instances"} class="hover:text-slate-200">Instances</a>
            <a href={~p"/alerts"} class="text-slate-200">Alerts</a>
            <a href={~p"/hub"} class="hover:text-slate-200">Hub</a>
          </nav>
        </div>
        <span class="text-sm text-slate-400">{@current_user.username}</span>
      </header>

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Alerts <span class="ml-2 text-sm text-slate-500">({length(@alerts)})</span>
        </h1>

        <div :if={@alerts == []} class="text-sm text-emerald-400">
          All clear — no non-OK checks in your scope.
        </div>

        <table :if={@alerts != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">State</th>
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Check</th>
              <th class="py-2 pr-4 font-medium">Summary</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={a <- @alerts} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span class={["rounded px-2 py-0.5 text-xs font-medium", state_class(a.check.state)]}>
                  {state_label(a.check.state)}
                </span>
              </td>
              <td class="py-2 pr-4">
                <a href={~p"/instances/#{a.inst.id}"} class="text-slate-200 hover:text-emerald-300">
                  {a.inst.name}
                </a>
              </td>
              <td class="py-2 pr-4 text-slate-400">{a.check.key}</td>
              <td class="py-2 pr-4 text-slate-300">{a.check.summary}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp state_label(1), do: "WARN"
  defp state_label(2), do: "CRIT"
  defp state_label(3), do: "UNKNOWN"
  defp state_label(_), do: "OK"

  defp state_class(2), do: "bg-red-900/60 text-red-300"
  defp state_class(1), do: "bg-amber-900/50 text-amber-300"
  defp state_class(3), do: "bg-slate-700 text-slate-300"
  defp state_class(_), do: "bg-emerald-900/50 text-emerald-300"
end
