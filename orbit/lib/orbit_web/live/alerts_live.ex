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

    # Opens on the exported set (python parity): those are the checks that
    # actually page someone. Note the interaction with base-OFF selection —
    # on a fleet whose include rules are not curated yet this shows few or no
    # rows even while CRITs exist; the "Checkmk-exported" chip toggles back
    # to everything.
    {:ok, socket |> assign(severity_filter: "all", exported_filter: "exported") |> load()}
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

  def handle_event("exported_filter", %{"val" => v}, socket)
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
            base_url: (record && record.base_url) || "",
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

  # Check families ("ipsec.tunnel:3" → "ipsec.tunnel") with their worst state,
  # so the shape of the outage is readable before the first row. Built from the
  # alerts already in the socket — no second evaluate pass.
  defp family_tally(alerts) do
    alerts
    |> Enum.group_by(fn %{check: c} -> c.key |> String.split(":", parts: 2) |> hd() end)
    |> Enum.map(fn {family, list} ->
      worst = list |> Enum.map(& &1.check.state) |> Enum.max_by(&ServiceCheck.severity/1)

      %{
        family: family,
        count: length(list),
        tone: tone_for(worst)
      }
    end)
    |> Enum.sort_by(&{-ServiceCheck.severity(state_for(&1.tone)), -&1.count, &1.family})
  end

  defp tone_for(2), do: :crit
  defp tone_for(1), do: :warn
  defp tone_for(_unknown), do: :neutral

  defp state_for(:crit), do: 2
  defp state_for(:warn), do: 1
  defp state_for(:neutral), do: 3

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
        families: family_tally(assigns.alerts),
        crit: Enum.count(assigns.alerts, &(&1.check.state == 2)),
        warn: Enum.count(assigns.alerts, &(&1.check.state == 1)),
        unknown: Enum.count(assigns.alerts, &(&1.check.state == 3))
      )

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:alerts} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:alerts} class="h-5 w-5 text-base-content/60" /> Alerts
            <span class="ml-2 text-sm text-base-content/60">({length(@alerts)})</span>
          </h1>
          <button
            phx-click="refresh_now"
            class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
          >
            Refresh
          </button>
        </div>

        <.data_note>
          Every non-OK check of your firewalls, worst first — the exact set the Checkmk and
          Prometheus exports and the per-instance tab show, across every transport (agent-push,
          direct-API polled and Securepoint alike).
          UNKNOWN means "could not check", which is never silently OK. Two
          overlays soften the picture on purpose: while an agent is silent its box shows one
          <span class="font-mono">agent</span>
          alert and its other CRITs are capped to WARN, and a box in maintenance is capped to
          WARN entirely — so a quiet page can still mean a loud box.
        </.data_note>

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
            color="text-error"
            event="severity_filter"
            value_name="crit"
            active={@severity_filter == "crit"}
          />
          <.kpi_tile
            label="WARN"
            value={@warn}
            color="text-warning"
            event="severity_filter"
            value_name="warn"
            active={@severity_filter == "warn"}
          />
          <.kpi_tile
            label="UNKNOWN"
            value={@unknown}
            color="text-base-content/70"
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
              class="w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </form>
          <div class="flex gap-2">
            <button
              :for={{v, label} <- [{"exported", "Checkmk-exported"}, {"excluded", "Excluded"}]}
              phx-click="exported_filter"
              phx-value-val={v}
              class={chip(@exported_filter == v)}
            >
              {label}
            </button>
          </div>
        </div>

        <div :if={@families != []} class="mb-3 flex flex-wrap gap-2">
          <.count_chip
            :for={f <- @families}
            label={f.family}
            count={f.count}
            tone={f.tone}
            title="check family, worst state"
          />
        </div>

        <div :if={@alerts == []} class="text-sm text-primary">
          All clear — no non-OK checks in your scope.
        </div>
        <div :if={@alerts != [] and @rows == []} class="text-sm text-base-content/60">
          No matches.
        </div>

        <div class="overflow-x-auto">
          <table :if={@rows != []} class="w-full min-w-[46rem] text-left text-sm">
            <thead class="sticky top-0 z-10 bg-base-100 text-base-content/60">
              <tr class="border-b border-base-300">
                <th class="py-2 pr-4 font-medium">State</th>
                <th class="py-2 pr-4 font-medium">Instance</th>
                <th class="py-2 pr-4 font-medium">Check</th>
                <th class="py-2 pr-4 font-medium">Summary</th>
                <th class="py-2 pr-4 font-medium">Checkmk</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={a <- @rows} class="border-b border-base-300/50">
                <td class="py-2 pr-4">
                  <span class={["rounded px-2 py-0.5 text-xs font-medium", state_class(a.check.state)]}>
                    {state_label(a.check.state)}
                  </span>
                </td>
                <td class="py-2 pr-4">
                  <a href={~p"/instances/#{a.inst.id}"} class="text-base-content hover:text-primary">
                    {a.inst.name}
                  </a>
                  <.base_url_link base_url={a.base_url} />
                  <.webui_link instance_id={a.inst.id} openable={a.gui_openable} />
                  <.shell_link instance_id={a.inst.id} shell_enabled={a.shell_enabled} />
                </td>
                <td class="py-2 pr-4 text-base-content/70">{a.check.key}</td>
                <td class="py-2 pr-4 text-base-content/80">{a.check.summary}</td>
                <td class="py-2 pr-4 text-xs">
                  <span :if={a.exported} class="text-primary">exported</span>
                  <span :if={not a.exported} class="text-base-content/40">excluded</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>
    """
  end

  defp state_label(1), do: "WARN"
  defp state_label(2), do: "CRIT"
  defp state_label(3), do: "UNKNOWN"
  defp state_label(_), do: "OK"

  defp state_class(2), do: "bg-error/20 text-error"
  defp state_class(1), do: "bg-warning/20 text-warning"
  defp state_class(3), do: "bg-base-300 text-base-content/70"
  defp state_class(_), do: "bg-primary/20 text-primary"
end
