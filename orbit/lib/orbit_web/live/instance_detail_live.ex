defmodule OrbitWeb.InstanceDetailLive do
  @moduledoc """
  Per-instance detail: static instance record + live metrics from the hub
  section cache (raw agent sections — cpu.total_pct, memory.used_pct,
  disks[], system, uptime) + the evaluated checks for this instance — the
  per-instance surface of the four-surface parity rule, run through the same
  Orbit.Checks.Export chain the Checkmk/Prometheus/Alerts surfaces use.
  Scoped via get_instance (invariant 1): a missing or out-of-scope id
  redirects to /instances, never revealing existence.

  Refreshes metrics on a 5s live-agent tier timer and on hub roster edges.
  """

  use OrbitWeb, :live_view

  alias Orbit.Auth.Scope
  alias Orbit.Checks.Export
  alias Orbit.Checks.ServiceCheck
  alias Orbit.Hub
  alias Orbit.Instances.Instance

  @refresh_ms 5_000

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user) do
      if connected?(socket) do
        Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
        Process.send_after(self(), :refresh, @refresh_ms)
      end

      {:ok, socket |> assign(instance: inst) |> load_metrics()}
    else
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load_metrics(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load_metrics(socket)}
  end

  defp load_metrics(socket) do
    entry = Hub.cache_entry(socket.assigns.instance.id)
    status = entry["status"] || %{}

    assign(socket,
      connected: Hub.get(socket.assigns.instance.id) != nil,
      cpu: get_in(status, ["cpu", "total_pct"]),
      memory: status["memory"],
      disks: status["disks"] || [],
      system: status["system"] || %{},
      uptime: status["uptime"],
      # Raw ipsec section is a map %{"running", "tunnels" => [...]} — iterate the
      # tunnel list, not the map (else :for yields {k,v} tuples). Real OPNsense
      # data exposed this; synthetic pushes had used a bare list.
      ipsec: (entry["ipsec"] || %{})["tunnels"] || [],
      last_seen: entry["last_metrics_ts"],
      checks: instance_checks(socket.assigns.instance)
    )
  end

  # Per-instance evaluated checks — same evaluate→overlay chain as the exports
  # and Alerts (four-surface parity). Direct-poll instances have no cached
  # sections yet (poller not ported), so only agent-mode instances get checks.
  defp instance_checks(inst) do
    if Instance.agent_mode?(inst) do
      inst
      |> Export.checks_for(DateTime.utc_now())
      |> Enum.sort_by(&{-ServiceCheck.severity(&1.state), &1.key})
    else
      []
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-6 flex items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">{@instance.name}</h1>
          <span class={["rounded px-2 py-0.5 text-xs", conn_badge(@connected)]}>
            {if @connected, do: "agent connected", else: "no agent"}
          </span>
          <a
            :if={@instance.shell_enabled}
            href={~p"/instances/#{@instance.id}/terminal"}
            class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Terminal
          </a>
        </div>

        <div class="grid gap-6 md:grid-cols-2">
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 class="mb-3 text-sm font-medium text-slate-400">Instance</h2>
            <dl class="space-y-1 text-sm">
              <.kv label="Type" value={@instance.device_type} />
              <.kv label="Transport" value={@instance.transport} />
              <.kv label="Base URL" value={Orbit.Instances.Instance.primary_base_url(@instance)} />
              <.kv label="Location" value={@instance.location || "—"} />
            </dl>
          </div>

          <div class="rounded-lg border border-slate-800 bg-slate-900 p-4">
            <h2 class="mb-3 text-sm font-medium text-slate-400">Live</h2>
            <div :if={not @connected and @system == %{}} class="text-sm text-slate-500">
              No live data — agent not pushing.
            </div>
            <dl :if={@connected or @system != %{}} class="space-y-1 text-sm">
              <.kv label="Hostname" value={@system["hostname"] || "—"} />
              <.kv label="OS" value={@system["os"] || "—"} />
              <.kv label="Uptime" value={@uptime || "—"} />
              <.kv label="CPU" value={pct(@cpu)} />
              <.kv label="Memory" value={mem_text(@memory)} />
            </dl>
          </div>
        </div>

        <div :if={@checks != []} class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">
            Checks <span class="text-slate-500">({length(@checks)})</span>
          </h2>
          <table class="w-full text-left text-sm">
            <tbody>
              <tr :for={c <- @checks} class="border-b border-slate-800/50 last:border-0">
                <td class="w-16 py-1.5 pr-4 align-top">
                  <span class={["rounded px-2 py-0.5 text-xs font-medium", state_class(c.state)]}>
                    {state_label(c.state)}
                  </span>
                </td>
                <td class="whitespace-nowrap py-1.5 pr-4 align-top text-slate-400">{c.key}</td>
                <td class="py-1.5 align-top text-slate-300">{c.summary}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div :if={@disks != []} class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">Disks</h2>
          <ul class="space-y-1 text-sm">
            <li :for={d <- @disks} class="flex justify-between text-slate-300">
              <span class="text-slate-400">{d["mountpoint"] || d["device"]}</span>
              <span>{pct(d["used_pct"])}</span>
            </li>
          </ul>
        </div>

        <div :if={@ipsec != []} class="mt-6 rounded-lg border border-slate-800 bg-slate-900 p-4">
          <h2 class="mb-3 text-sm font-medium text-slate-400">IPsec tunnels</h2>
          <ul class="space-y-1 text-sm">
            <li :for={t <- @ipsec} class="flex justify-between text-slate-300">
              <span class="text-slate-400">{t["name"] || t["child_name"] || "tunnel"}</span>
              <span class={tunnel_color(t["state"])}>{t["state"] || "?"}</span>
            </li>
          </ul>
        </div>
      </section>
    </main>
    """
  end

  attr :label, :string, required: true
  attr :value, :string, required: true

  defp kv(assigns) do
    ~H"""
    <div class="flex justify-between">
      <dt class="text-slate-500">{@label}</dt>
      <dd class="text-slate-200">{@value}</dd>
    </div>
    """
  end

  defp conn_badge(true), do: "bg-emerald-900/50 text-emerald-300"
  defp conn_badge(false), do: "bg-slate-800 text-slate-500"

  defp pct(nil), do: "—"
  defp pct(v) when is_number(v), do: "#{Float.round(v / 1, 1)}%"
  defp pct(_), do: "—"

  defp mem_text(%{"used_pct" => up, "total_mb" => tot})
       when is_number(up) and is_number(tot) and tot > 0 do
    "#{Float.round(up / 1, 1)}% of #{round(tot)} MB"
  end

  # Some agents (the Linux node) report used_pct without a usable total_mb —
  # show just the percentage instead of a nonsensical "of 0 MB".
  defp mem_text(%{"used_pct" => up}) when is_number(up), do: "#{Float.round(up / 1, 1)}%"

  defp mem_text(_), do: "—"

  defp tunnel_color("up"), do: "text-emerald-400"
  defp tunnel_color("connected"), do: "text-emerald-400"
  defp tunnel_color(_), do: "text-amber-400"

  defp state_label(1), do: "WARN"
  defp state_label(2), do: "CRIT"
  defp state_label(3), do: "UNKNOWN"
  defp state_label(_), do: "OK"

  defp state_class(2), do: "bg-red-900/60 text-red-300"
  defp state_class(1), do: "bg-amber-900/50 text-amber-300"
  defp state_class(3), do: "bg-slate-700 text-slate-300"
  defp state_class(_), do: "bg-emerald-900/50 text-emerald-300"
end
