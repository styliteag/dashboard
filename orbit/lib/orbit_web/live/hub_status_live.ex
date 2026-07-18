defmodule OrbitWeb.HubStatusLive do
  @moduledoc """
  Live agent-hub roster — the first real LiveView (the rewrite's whole point
  is LiveView instead of react). Shows every connected agent the caller may
  see, updating on connect/disconnect via PubSub and refreshing the live
  metrics on a tier timer (10s, the react hub-status refetch tier).

  Hub state is UNSCOPED in-memory data (invariant 5): the roster is filtered
  per-entry through Scope before it ever reaches the socket.
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit
  import OrbitWeb.Components.MetricChart

  alias Orbit.Auth.Scope
  alias Orbit.Hub

  @refresh_ms 10_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
      Process.send_after(self(), :refresh, @refresh_ms)
    end

    {:ok, load(socket)}
  end

  defp load(socket) do
    stats = Hub.stats()

    assign(socket,
      agents: visible_agents(socket.assigns.current_user),
      push_rate: Orbit.Metrics.push_rate("6h"),
      counters: stats.counters,
      started_at: stats.started_at,
      crit_tabs: crit_tabs(socket.assigns.current_user)
    )
  end

  # Red/CRIT alerts grouped by the page that owns them (HubStatusPage
  # alertTab) — each chip links where the operator actually fixes it.
  defp crit_tabs(user) do
    user
    |> Orbit.Checks.Export.evaluated(DateTime.utc_now())
    |> Enum.flat_map(fn {_inst, checks} -> Enum.filter(checks, &(&1.state == 2)) end)
    |> Enum.group_by(&alert_tab(&1.key))
    |> Enum.map(fn {{to, label}, checks} -> %{to: to, label: label, count: length(checks)} end)
    |> Enum.sort_by(&(-&1.count))
  end

  defp alert_tab(key) do
    cat = key |> String.split(":", parts: 2) |> hd()

    cond do
      cat == "cert" -> {"/certificates", "Certificates"}
      cat in ["ipsec.tunnel", "ipsec.tunnel_ping", "ipsec.service"] -> {"/vpn", "VPN"}
      cat == "connectivity" -> {"/connectivity", "Connectivity"}
      cat == "gateway" -> {"/alerts?q=gateway", "Gateways"}
      cat == "firmware" -> {"/firmware", "Firmware"}
      true -> {"/alerts", "System"}
    end
  end

  # Counters that indicate something is wrong — rendered red when non-zero.
  defp error_counters do
    [
      {:auth_failures, "Auth failures"},
      {:json_errors, "Bad JSON frames"},
      {:unknown_messages, "Unknown messages"}
    ]
  end

  defp traffic_counters do
    [
      {:pushes, "Metric pushes"},
      {:command_results, "Command results"},
      {:tunnel_frames, "Tunnel frames"},
      {:pongs, "Pongs"},
      {:connects, "Connects"},
      {:disconnects, "Disconnects"}
    ]
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  @impl true
  def handle_event("row_gui_open", %{"id" => id}, socket) do
    {:noreply, gui_open_row(socket, id)}
  end

  # Scope the unscoped hub roster: keep only instances the user may see, then
  # decorate each with its live cpu from the section cache.
  defp visible_agents(user) do
    Hub.list_connected()
    |> Enum.flat_map(fn agent ->
      case Scope.get_instance(agent.instance_id, user) do
        nil ->
          []

        inst ->
          # RAW agent section key is cpu.total_pct (not .total) — see collect_cpu.
          cpu =
            Hub.cache_entry(agent.instance_id)
            |> get_in(["status", "cpu", "total_pct"])

          [
            %{
              instance_id: agent.instance_id,
              instance_name: inst.name,
              shell_enabled: inst.shell_enabled,
              gui_openable: Orbit.GUI.openable(inst) == :ok,
              version: agent.agent_version,
              platform: agent.platform,
              pushes: agent.pushes,
              connected_at: agent.connected_at,
              last_push_at: agent.last_push_at,
              cpu: cpu,
              update_error: agent.last_update_error
            }
          ]
      end
    end)
    |> Enum.sort_by(& &1.instance_name)
  end

  @impl true
  def render(assigns) do
    per_minute =
      case assigns.push_rate do
        # The newest bucket is the still-filling current minute — report the
        # last full one (HubStatusPage parity).
        rate when length(rate) > 1 -> trunc(Enum.at(rate, -2).value)
        _ -> 0
      end

    assigns =
      assign(assigns,
        total_pushes: assigns.agents |> Enum.map(& &1.pushes) |> Enum.sum(),
        update_errors: Enum.count(assigns.agents, & &1.update_error),
        served_version: Orbit.Agent.Package.served_version(),
        per_minute: per_minute,
        errors_total:
          error_counters()
          |> Enum.map(fn {k, _} -> Map.get(assigns.counters, k, 0) end)
          |> Enum.sum()
      )

    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:hub} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-1 text-lg font-medium text-slate-200">
          Hub status <span class="ml-2 text-sm text-slate-500">({length(@agents)} connected)</span>
        </h1>
        <p class="mb-4 text-xs text-slate-500">
          In-memory since {Calendar.strftime(@started_at, "%Y-%m-%d %H:%M UTC")} — a restart
          resets these numbers.
        </p>

        <div class="mb-4 grid gap-3 sm:grid-cols-4">
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div class="text-xs text-slate-500">Connected</div>
            <div class="text-2xl font-semibold text-emerald-400">{length(@agents)}</div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div class="text-xs text-slate-500">Pushes / min</div>
            <div class="text-2xl font-semibold text-sky-400">{@per_minute}</div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div class="text-xs text-slate-500">Total pushes</div>
            <div class="text-2xl font-semibold text-slate-100">{@total_pushes}</div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div class="text-xs text-slate-500">Errors total</div>
            <div class={[
              "text-2xl font-semibold",
              if(@errors_total > 0, do: "text-red-400", else: "text-slate-100")
            ]}>
              {@errors_total}
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div class="text-xs text-slate-500">Update errors</div>
            <div class={[
              "text-2xl font-semibold",
              if(@update_errors > 0, do: "text-amber-400", else: "text-slate-100")
            ]}>
              {@update_errors}
            </div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div class="text-xs text-slate-500">Served agent</div>
            <div class="text-2xl font-semibold text-slate-100">{@served_version || "—"}</div>
          </div>
        </div>

        <%!-- Fleet push activity (HubStatusPage rate-chart parity): pushes
             per minute-bucket over the last 6h, counted from the metric
             rows every push writes. --%>
        <div class="mb-4 max-w-xl">
          <.metric_chart
            label="Pushes / min (fleet, 6h)"
            points={@push_rate}
            color="#38bdf8"
            domain_max={:auto}
          />
        </div>

        <%!-- Red/CRIT alerts by owning tab — chips link where you fix it. --%>
        <div :if={@crit_tabs != []} class="mb-4">
          <h2 class="mb-2 text-sm font-semibold text-slate-300">Red / CRIT alerts by tab</h2>
          <div class="flex flex-wrap gap-2">
            <a
              :for={t <- @crit_tabs}
              href={t.to}
              class="rounded-lg border border-red-900/60 bg-red-900/20 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/30"
            >
              {t.label}: {t.count}
            </a>
          </div>
        </div>

        <h2 class="mb-2 mt-6 text-sm font-semibold text-slate-300">Error counters</h2>
        <div class="mb-4 grid gap-3 sm:grid-cols-3">
          <div
            :for={{key, label} <- error_counters()}
            class="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3"
          >
            <p class="text-xs text-slate-500">{label}</p>
            <p class={[
              "text-lg font-semibold",
              if(Map.get(@counters, key, 0) > 0, do: "text-red-400", else: "text-slate-200")
            ]}>
              {Map.get(@counters, key, 0)}
            </p>
          </div>
        </div>

        <h2 class="mb-2 mt-6 text-sm font-semibold text-slate-300">Message counters</h2>
        <div class="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <div
            :for={{key, label} <- traffic_counters()}
            class="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3"
          >
            <p class="text-xs text-slate-500">{label}</p>
            <p class="text-lg font-semibold text-slate-200">{Map.get(@counters, key, 0)}</p>
          </div>
        </div>

        <div :if={@agents == []} class="text-sm text-slate-500">
          No agents connected in your scope.
        </div>

        <table :if={@agents != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Platform</th>
              <th class="py-2 pr-4 font-medium">Version</th>
              <th class="py-2 pr-4 font-medium">CPU</th>
              <th class="py-2 pr-4 font-medium">Pushes</th>
              <th class="py-2 pr-4 font-medium">Connected since</th>
              <th class="py-2 pr-4 font-medium">Last push</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={a <- @agents} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <a
                  href={~p"/instances/#{a.instance_id}"}
                  class="text-slate-200 hover:text-emerald-300"
                >
                  {a.instance_name}
                </a>
                <.webui_link instance_id={a.instance_id} openable={a.gui_openable} />
                <.shell_link instance_id={a.instance_id} shell_enabled={a.shell_enabled} />
              </td>
              <td class="py-2 pr-4 text-slate-400">{a.platform}</td>
              <td class="py-2 pr-4 text-slate-400">
                {a.version}
                <span :if={a.update_error} class="ml-1 text-amber-400" title={a.update_error}>
                  ⚠
                </span>
              </td>
              <td class="py-2 pr-4 text-slate-300">{cpu_text(a.cpu)}</td>
              <td class="py-2 pr-4 text-slate-400">{a.pushes}</td>
              <td class="py-2 pr-4 text-slate-500">{push_text(a.connected_at)}</td>
              <td class="py-2 pr-4 text-slate-500">{push_text(a.last_push_at)}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp cpu_text(nil), do: "—"
  defp cpu_text(cpu) when is_number(cpu), do: "#{Float.round(cpu / 1, 1)}%"
  defp cpu_text(_), do: "—"

  defp push_text(nil), do: "—"
  defp push_text(%DateTime{} = dt), do: Calendar.strftime(dt, "%H:%M:%S UTC")
end
