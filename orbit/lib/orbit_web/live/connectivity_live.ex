defmodule OrbitWeb.ConnectivityLive do
  @moduledoc """
  Fleet connectivity monitors — one row per configured ping monitor across the
  caller's visible push instances, read from the hub `connectivity` section and
  scored by the same connectivity check family (no reply ⇒ CRIT, misconfigured
  ⇒ WARN, 'none' skipped). RTT/loss come straight from the check metrics so the
  page agrees with Alerts and the exports. Worst-first, scoped (invariant 5);
  roster PubSub + 30s tier timer (monitors refresh at push cadence).
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit

  alias Orbit.Checks.Evaluate
  alias Orbit.Checks.ServiceCheck
  alias Orbit.Hub
  alias Orbit.Instances

  @refresh_ms 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
      Process.send_after(self(), :refresh, @refresh_ms)
    end

    {:ok, socket |> assign(search: "", state_filter: "all") |> load()}
  end

  @impl true
  def handle_event("search", %{"q" => q}, socket), do: {:noreply, assign(socket, search: q)}

  def handle_event("state_filter", %{"bucket" => b}, socket) when b in ~w(all ok warn crit) do
    b = if socket.assigns.state_filter == b, do: "all", else: b
    {:noreply, assign(socket, state_filter: b)}
  end

  def handle_event("row_gui_open", %{"id" => id}, socket) do
    {:noreply, gui_open_row(socket, id)}
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load(socket)}

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
        monitors = Hub.cache_entry(inst.id)["connectivity"] || []

        gui_openable = Orbit.GUI.openable(inst) == :ok

        for check <- Evaluate.connectivity_checks(monitors) do
          %{
            instance_id: inst.id,
            instance_name: inst.name,
            shell_enabled: inst.shell_enabled,
            gui_openable: gui_openable,
            check: check,
            rtt: metric_val(check, "ping_rtt_ms"),
            loss: metric_val(check, "ping_loss_pct")
          }
        end
      end)
      |> Enum.sort_by(fn %{check: c, instance_name: n} ->
        {-ServiceCheck.severity(c.state), n, c.key}
      end)

    assign(socket, rows: rows)
  end

  defp visible(a) do
    q = String.downcase(a.search)

    a.rows
    |> Enum.filter(fn r ->
      q == "" or
        String.contains?(String.downcase(r.instance_name), q) or
        String.contains?(String.downcase(r.check.summary || ""), q)
    end)
    |> Enum.filter(fn r ->
      case a.state_filter do
        "all" -> true
        "ok" -> r.check.state == 0
        "warn" -> r.check.state in [1, 3]
        "crit" -> r.check.state == 2
      end
    end)
  end

  defp metric_val(%ServiceCheck{metrics: metrics}, name) do
    case Enum.find(metrics, &(&1.name == name)) do
      %{value: v} when is_number(v) -> v
      _ -> nil
    end
  end

  @impl true
  def render(assigns) do
    assigns =
      assign(assigns,
        visible_rows: visible(assigns),
        ok: Enum.count(assigns.rows, &(&1.check.state == 0)),
        warn: Enum.count(assigns.rows, &(&1.check.state in [1, 3])),
        crit: Enum.count(assigns.rows, &(&1.check.state == 2))
      )

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:connectivity} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-base-content">
          Connectivity monitors
          <span class="ml-2 text-sm text-base-content/60">({length(@rows)})</span>
        </h1>

        <div class="mb-4 grid gap-3 sm:grid-cols-4">
          <.kpi_tile
            label="Total"
            value={length(@rows)}
            event="state_filter"
            value_name="all"
            active={@state_filter == "all"}
          />
          <.kpi_tile
            label="OK"
            value={@ok}
            color="text-primary"
            event="state_filter"
            value_name="ok"
            active={@state_filter == "ok"}
          />
          <.kpi_tile
            label="WARN"
            value={@warn}
            color="text-warning"
            event="state_filter"
            value_name="warn"
            active={@state_filter == "warn"}
          />
          <.kpi_tile
            label="CRIT"
            value={@crit}
            color="text-error"
            event="state_filter"
            value_name="crit"
            active={@state_filter == "crit"}
          />
        </div>

        <form phx-change="search" onsubmit="return false" class="mb-3 max-w-md">
          <input
            type="text"
            name="q"
            value={@search}
            placeholder="Search instance, monitor…"
            phx-debounce="300"
            class="w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </form>

        <div :if={@rows == []} class="text-sm text-base-content/60">
          No connectivity monitors reported in your scope.
        </div>
        <div :if={@rows != [] and @visible_rows == []} class="text-sm text-base-content/60">
          No matches.
        </div>

        <table :if={@visible_rows != []} class="w-full text-left text-sm">
          <thead class="text-base-content/60">
            <tr class="border-b border-base-300">
              <th class="py-2 pr-4 font-medium">State</th>
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Monitor</th>
              <th class="py-2 pr-4 text-right font-medium">RTT</th>
              <th class="py-2 pr-4 text-right font-medium">Loss</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={r <- @visible_rows} class="border-b border-base-300/50">
              <td class="py-2 pr-4">
                <span class={["rounded px-1.5 py-0.5 text-xs", state_class(r.check.state)]}>
                  {state_label(r.check.state)}
                </span>
              </td>
              <td class="py-2 pr-4">
                <a
                  href={~p"/instances/#{r.instance_id}"}
                  class="text-base-content hover:text-primary"
                >
                  {r.instance_name}
                </a>
                <.webui_link instance_id={r.instance_id} openable={r.gui_openable} />
                <.shell_link instance_id={r.instance_id} shell_enabled={r.shell_enabled} />
              </td>
              <td class="py-2 pr-4 text-base-content/80">{r.check.summary}</td>
              <td class="py-2 pr-4 text-right text-base-content/70">{rtt_text(r.rtt)}</td>
              <td class="py-2 pr-4 text-right text-base-content/70">{loss_text(r.loss)}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp rtt_text(nil), do: "—"
  defp rtt_text(v) when is_number(v), do: "#{Float.round(v / 1, 1)} ms"

  defp loss_text(nil), do: "—"
  defp loss_text(v) when is_number(v), do: "#{Float.round(v / 1, 0)}%"

  defp state_label(0), do: "OK"
  defp state_label(1), do: "WARN"
  defp state_label(2), do: "CRIT"
  defp state_label(_), do: "UNKNOWN"

  defp state_class(0), do: "bg-primary/20 text-primary"
  defp state_class(1), do: "bg-warning/20 text-warning"
  defp state_class(2), do: "bg-error/20 text-error"
  defp state_class(_), do: "bg-neutral text-base-content/80"
end
