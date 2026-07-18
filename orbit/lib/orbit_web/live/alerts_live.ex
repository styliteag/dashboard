defmodule OrbitWeb.AlertsLive do
  @moduledoc """
  Fleet alerts — every non-OK evaluated check across the caller's visible
  instances, worst-first. Runs the full evaluate→overlay chain (Orbit.Checks
  .Export.evaluated) so it shows exactly what the Checkmk/Prometheus exports
  and the per-instance view show (the four-surface parity rule). Scoped
  through the instance list (invariant 5). Refreshes on hub roster edges +
  a 30s tier timer.

  Interaction parity with AlertsPage.tsx: severity KPI tiles double as
  filters, search with a `?q=` deep link (the instances list's CRIT/WARN
  badges land here pre-filtered), a checkmk-exported column + filter, and
  the WebUI/Terminal quick links per row.
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit

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

    {:ok, socket |> assign(severity_filter: "all", exported_filter: "all") |> load()}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, assign(socket, search: params["q"] || "")}
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  @impl true
  def handle_event("search", %{"q" => q}, socket) do
    {:noreply, assign(socket, search: q)}
  end

  def handle_event("severity_filter", %{"bucket" => b}, socket)
      when b in ~w(all crit warn unknown) do
    b = if socket.assigns.severity_filter == b, do: "all", else: b
    {:noreply, assign(socket, severity_filter: b)}
  end

  def handle_event("exported_filter", %{"value" => v}, socket)
      when v in ~w(all exported excluded) do
    v = if socket.assigns.exported_filter == v, do: "all", else: v
    {:noreply, assign(socket, exported_filter: v)}
  end

  def handle_event("refresh_now", _params, socket), do: {:noreply, load(socket)}

  def handle_event("row_gui_open", %{"id" => id}, socket) do
    {:noreply, gui_open_row(socket, id)}
  end

  defp load(socket) do
    # Export.evaluated yields a slim inst MAP (id/name/mode/device_type),
    # not the Instance struct — join the full records for the quick links.
    full =
      socket.assigns.current_user
      |> Orbit.Instances.list_visible()
      |> Map.new(&{&1.id, &1})

    alerts =
      socket.assigns.current_user
      |> Export.evaluated(DateTime.utc_now())
      |> Enum.flat_map(fn {inst, checks} ->
        record = full[inst.id]

        for c <- checks, c.state != 0 do
          %{
            inst: inst,
            shell_enabled: (record && record.shell_enabled) || false,
            check: c,
            exported: Orbit.Selection.is_on_live("checkmk", c.key, inst.id),
            gui_openable: record != nil and Orbit.GUI.openable(record) == :ok
          }
        end
      end)
      # Worst-first: CRIT > WARN > UNKNOWN, then by instance/key for stability.
      |> Enum.sort_by(fn %{inst: i, check: c} ->
        {-ServiceCheck.severity(c.state), i.name, c.key}
      end)

    assign(socket, alerts: alerts)
  end

  defp visible(a) do
    q = String.downcase(a.search || "")

    a.alerts
    |> Enum.filter(fn al ->
      q == "" or
        String.contains?(String.downcase(al.inst.name), q) or
        String.contains?(String.downcase(al.check.key), q) or
        String.contains?(String.downcase(al.check.summary || ""), q)
    end)
    |> Enum.filter(fn al ->
      case a.severity_filter do
        "all" -> true
        "crit" -> al.check.state == 2
        "warn" -> al.check.state == 1
        "unknown" -> al.check.state == 3
      end
    end)
    |> Enum.filter(fn al ->
      case a.exported_filter do
        "all" -> true
        "exported" -> al.exported
        "excluded" -> not al.exported
      end
    end)
  end

  @impl true
  def render(assigns) do
    assigns =
      assign(assigns,
        rows: visible(assigns),
        crit: Enum.count(assigns.alerts, &(&1.check.state == 2)),
        warn: Enum.count(assigns.alerts, &(&1.check.state == 1)),
        unknown: Enum.count(assigns.alerts, &(&1.check.state == 3))
      )

    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:alerts} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">
            Alerts <span class="ml-2 text-sm text-slate-500">({length(@alerts)})</span>
          </h1>
          <button
            phx-click="refresh_now"
            class="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
          >
            Refresh
          </button>
        </div>

        <div class="mb-4 grid gap-3 sm:grid-cols-4">
          <.kpi_tile
            label="Total"
            value={length(@alerts)}
            event="severity_filter"
            value_name="all"
            active={@severity_filter == "all"}
          />
          <.kpi_tile
            label="CRIT"
            value={@crit}
            color="text-red-400"
            event="severity_filter"
            value_name="crit"
            active={@severity_filter == "crit"}
          />
          <.kpi_tile
            label="WARN"
            value={@warn}
            color="text-amber-400"
            event="severity_filter"
            value_name="warn"
            active={@severity_filter == "warn"}
          />
          <.kpi_tile
            label="UNKNOWN"
            value={@unknown}
            color="text-slate-400"
            event="severity_filter"
            value_name="unknown"
            active={@severity_filter == "unknown"}
          />
        </div>

        <div class="mb-3 flex flex-wrap items-center gap-3">
          <form phx-change="search" onsubmit="return false" class="max-w-md flex-1">
            <input
              type="text"
              name="q"
              value={@search}
              placeholder="Search instance, check, summary…"
              phx-debounce="300"
              class="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
            />
          </form>
          <div class="flex gap-2">
            <button
              :for={{v, label} <- [{"exported", "Checkmk-exported"}, {"excluded", "Excluded"}]}
              phx-click="exported_filter"
              phx-value-value={v}
              class={chip(@exported_filter == v)}
            >
              {label}
            </button>
          </div>
        </div>

        <div :if={@alerts == []} class="text-sm text-emerald-400">
          All clear — no non-OK checks in your scope.
        </div>
        <div :if={@alerts != [] and @rows == []} class="text-sm text-slate-500">
          No matches.
        </div>

        <table :if={@rows != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">State</th>
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Check</th>
              <th class="py-2 pr-4 font-medium">Summary</th>
              <th class="py-2 pr-4 font-medium">Checkmk</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={a <- @rows} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span class={["rounded px-2 py-0.5 text-xs font-medium", state_class(a.check.state)]}>
                  {state_label(a.check.state)}
                </span>
              </td>
              <td class="py-2 pr-4">
                <a href={~p"/instances/#{a.inst.id}"} class="text-slate-200 hover:text-emerald-300">
                  {a.inst.name}
                </a>
                <.webui_link instance_id={a.inst.id} openable={a.gui_openable} />
                <.shell_link instance_id={a.inst.id} shell_enabled={a.shell_enabled} />
              </td>
              <td class="py-2 pr-4 text-slate-400">{a.check.key}</td>
              <td class="py-2 pr-4 text-slate-300">{a.check.summary}</td>
              <td class="py-2 pr-4 text-xs">
                <span :if={a.exported} class="text-emerald-500">exported</span>
                <span :if={not a.exported} class="text-slate-600">excluded</span>
              </td>
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
