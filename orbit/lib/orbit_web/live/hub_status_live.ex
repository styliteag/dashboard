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
      push_p95_ms: Map.get(stats, :push_p95_ms),
      push_samples: Map.get(stats, :push_samples, 0),
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

  # {label, count} pairs for the chip row above the roster, biggest group
  # first. Built from the roster the socket already holds — no extra query,
  # and nothing claimed about boxes that are not connected.
  defp tally(agents, fun) do
    agents
    |> Enum.map(fun)
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.frequencies()
    |> Enum.sort_by(fn {label, n} -> {-n, label} end)
  end

  # Two agent lines since the split (§28): a version chip is "outdated" when
  # ANY agent at that version is behind the served version of ITS OWN line —
  # a linux agent is never compared against the firewall package or vice
  # versa. The agent's hello platform maps 1:1 onto line_for/1.
  defp version_tally(agents, served) do
    agents
    |> Enum.reject(&(&1.version in [nil, ""]))
    |> Enum.group_by(& &1.version)
    |> Enum.map(fn {version, as} ->
      outdated =
        Enum.any?(as, fn a ->
          s = served[Orbit.Agent.Package.line_for(a.platform)]
          s != nil and a.version != s
        end)

      {version, length(as), outdated}
    end)
    |> Enum.sort_by(fn {version, n, _} -> {-n, version} end)
  end

  # One value while both lines serve the same version, else name them.
  defp served_label(served) do
    case served |> Map.values() |> Enum.reject(&is_nil/1) |> Enum.uniq() do
      [] -> nil
      [v] -> v
      _ -> "fw #{served.firewall || "—"} · linux #{served.linux || "—"}"
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
              base_url: inst.base_url,
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

    served = Orbit.Agent.Package.served_versions()

    assigns =
      assign(assigns,
        total_pushes: assigns.agents |> Enum.map(& &1.pushes) |> Enum.sum(),
        update_errors: Enum.count(assigns.agents, & &1.update_error),
        served_label: served_label(served),
        per_minute: per_minute,
        platform_tally: tally(assigns.agents, & &1.platform),
        version_tally: version_tally(assigns.agents, served),
        errors_total:
          error_counters()
          |> Enum.map(fn {k, _} -> Map.get(assigns.counters, k, 0) end)
          |> Enum.sum()
      )

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:hub} current_user={@current_user} />

      <section class="p-6">
        <h1 class="flex items-center gap-2 mb-1 text-lg font-medium text-base-content">
          <Icons.icon name={:hub} class="h-5 w-5 text-base-content/60" /> Hub status
          <span class="ml-2 text-sm text-base-content/60">({length(@agents)} connected)</span>
        </h1>
        <p class="mb-4 max-w-3xl text-xs leading-relaxed text-base-content/60">
          Live state of the agent WebSocket hub, in memory since {local_time_tag(
            @started_at,
            "datetime"
          )} — a backend restart resets every
          number on this page, and nothing here is persisted. Agents reconnect on their own.
          Tiles and the roster below are limited to your groups; the counter blocks and the
          chart are hub-wide totals across the whole fleet, so they can exceed what you see here.
        </p>

        <div class="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
          <.stat_tile label="Connected" value={length(@agents)} color="text-primary">
            <:hint>agents in your scope, right now</:hint>
          </.stat_tile>
          <.stat_tile label="Pushes / min" value={@per_minute} color="text-info">
            <:hint>fleet-wide, last full minute</:hint>
          </.stat_tile>
          <.stat_tile label="Total pushes" value={@total_pushes}>
            <:hint>your agents, since the hub started</:hint>
          </.stat_tile>
          <.stat_tile
            label="Errors total"
            value={@errors_total}
            color={if @errors_total > 0, do: "text-error", else: "text-base-content"}
          >
            <:hint>
              {if @errors_total > 0,
                do: "hub-wide — see the error counters below",
                else: "hub-wide; no rejected frames"}
            </:hint>
          </.stat_tile>
          <.stat_tile
            label="Update errors"
            value={@update_errors}
            color={if @update_errors > 0, do: "text-warning", else: "text-base-content"}
          >
            <:hint>
              {if @update_errors > 0,
                do: "your agents; last self-update failed",
                else: "your agents; last self-update clean"}
            </:hint>
          </.stat_tile>
          <.stat_tile label="Served agent" value={@served_label || "—"}>
            <:hint>version this dashboard offers on update</:hint>
          </.stat_tile>
          <%!-- Hub-side processing time per push. The number an operator
               needs when the dashboard starts feeling slow: it separates
               "a box is slow" (agent collect) from "the hub is saturated". --%>
          <.stat_tile
            label="Push p95"
            value={if @push_p95_ms, do: "#{@push_p95_ms} ms", else: "—"}
            color={if (@push_p95_ms || 0) >= 250, do: "text-warning", else: "text-base-content"}
          >
            <:hint>
              hub processing time, last {@push_samples} pushes{if Map.get(@counters, :slow_pushes, 0) >
                                                                    0,
                                                                  do:
                                                                    " · #{Map.get(@counters, :slow_pushes)} over 250 ms",
                                                                  else: ""}
            </:hint>
          </.stat_tile>
        </div>

        <%!-- Fleet push activity (HubStatusPage rate-chart parity): pushes
             per minute-bucket over the last 6h, counted from the metric
             rows every push writes. --%>
        <div class="mb-4">
          <.metric_chart
            label="Pushes / min (fleet, 6h)"
            points={@push_rate}
            color="#38bdf8"
            domain_max={:auto}
          />
        </div>

        <%!-- Red/CRIT alerts by owning tab — chips link where you fix it. --%>
        <div :if={@crit_tabs != []} class="mb-4">
          <h2 class="mb-2 text-sm font-semibold text-base-content/80">Red / CRIT alerts by tab</h2>
          <div class="flex flex-wrap gap-2">
            <a
              :for={t <- @crit_tabs}
              href={t.to}
              class="rounded-lg border border-error/40 bg-error/15 px-3 py-1.5 text-xs text-error hover:bg-error/25"
            >
              {t.label}: {t.count}
            </a>
          </div>
        </div>

        <h2 class="mb-1 mt-6 text-sm font-semibold text-base-content/80">Error counters</h2>
        <.data_note>
          Frames the hub refused, fleet-wide and not limited to your groups. Anything above zero
          means an agent (or something posing as one) is talking to the hub wrongly — these do
          not clear on their own, only on a backend restart.
        </.data_note>
        <div class="mb-4 grid max-w-3xl gap-3 sm:grid-cols-3">
          <div
            :for={{key, label} <- error_counters()}
            class="rounded-xl border border-base-300 bg-base-200/60 px-4 py-3"
          >
            <p class="text-xs text-base-content/60">{label}</p>
            <p class={[
              "text-lg font-semibold",
              if(Map.get(@counters, key, 0) > 0, do: "text-error", else: "text-base-content")
            ]}>
              {Map.get(@counters, key, 0)}
            </p>
          </div>
        </div>

        <h2 class="mb-1 mt-6 text-sm font-semibold text-base-content/80">Message counters</h2>
        <.data_note>
          Every frame type the hub has handled since it started — fleet-wide, so these exceed
          the "Total pushes" tile above, which counts only your agents. Pongs stay at zero by
          design: agent liveness runs on WebSocket control frames, the hub sends no
          application-level ping.
        </.data_note>
        <div class="mb-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
          <div
            :for={{key, label} <- traffic_counters()}
            class="rounded-xl border border-base-300 bg-base-200/60 px-4 py-3"
          >
            <p class="text-xs text-base-content/60">{label}</p>
            <p class="text-lg font-semibold text-base-content">{Map.get(@counters, key, 0)}</p>
          </div>
        </div>

        <h2 class="mb-1 mt-6 text-sm font-semibold text-base-content/80">Connected agents</h2>
        <.data_note>
          Push-mode boxes of your groups holding an open WebSocket right now. A box missing here
          is not necessarily down — it may be direct-API polled, or reconnecting; the Instances
          page is the authority on reachability.
        </.data_note>

        <div :if={@agents != []} class="mb-3 flex flex-wrap gap-2">
          <.count_chip :for={{label, n} <- @platform_tally} label={label} count={n} />
          <.count_chip
            :for={{version, n, outdated} <- @version_tally}
            label={version}
            count={n}
            tone={if outdated, do: :warn, else: :ok}
            title={if outdated, do: "update available", else: "current"}
          />
        </div>

        <.empty_state :if={@agents == []} title="No agents connected in your scope.">
          Push-mode boxes appear here once their WebSocket is up; direct-API polled devices
          never do. The Instances page is the authority on reachability.
        </.empty_state>

        <div class="overflow-x-auto">
          <table :if={@agents != []} class="w-full min-w-[46rem] text-left text-sm">
            <thead class="text-base-content/60">
              <tr class="border-b border-base-300">
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
              <tr :for={a <- @agents} class="border-b border-base-300/50">
                <td class="py-2 pr-4">
                  <a
                    href={~p"/instances/#{a.instance_id}"}
                    class="text-base-content hover:text-primary"
                  >
                    {a.instance_name}
                  </a>
                  <.base_url_link base_url={a.base_url} />
                  <.webui_link instance_id={a.instance_id} openable={a.gui_openable} />
                  <.shell_link instance_id={a.instance_id} shell_enabled={a.shell_enabled} />
                </td>
                <td class="py-2 pr-4 text-base-content/70">{a.platform}</td>
                <td class="py-2 pr-4 text-base-content/70">
                  {a.version}
                  <span :if={a.update_error} class="ml-1 text-warning" title={a.update_error}>
                    ⚠
                  </span>
                </td>
                <td class="py-2 pr-4 text-base-content/80">{cpu_text(a.cpu)}</td>
                <td class="py-2 pr-4 text-base-content/70">{a.pushes}</td>
                <td class="py-2 pr-4 text-base-content/60">{push_text(a.connected_at)}</td>
                <td class="py-2 pr-4 text-base-content/60">{push_text(a.last_push_at)}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>
    """
  end

  defp cpu_text(nil), do: "—"
  defp cpu_text(cpu) when is_number(cpu), do: "#{Float.round(cpu / 1, 1)}%"
  defp cpu_text(_), do: "—"

  defp push_text(nil), do: "—"
  defp push_text(%DateTime{} = dt), do: local_time_tag(dt, "time-sec")
end
