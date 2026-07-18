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

  alias Orbit.Auth.Scope
  alias Orbit.Hub

  @refresh_ms 10_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
      Process.send_after(self(), :refresh, @refresh_ms)
    end

    {:ok, assign(socket, agents: visible_agents(socket.assigns.current_user))}
  end

  @impl true
  def handle_info(:roster_changed, socket) do
    {:noreply, assign(socket, agents: visible_agents(socket.assigns.current_user))}
  end

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, assign(socket, agents: visible_agents(socket.assigns.current_user))}
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
    assigns =
      assign(assigns,
        total_pushes: assigns.agents |> Enum.map(& &1.pushes) |> Enum.sum(),
        update_errors: Enum.count(assigns.agents, & &1.update_error),
        served_version: Orbit.Agent.Package.served_version()
      )

    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:hub} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Connected agents <span class="ml-2 text-sm text-slate-500">({length(@agents)})</span>
        </h1>

        <div class="mb-4 grid gap-3 sm:grid-cols-4">
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div class="text-xs text-slate-500">Connected</div>
            <div class="text-2xl font-semibold text-emerald-400">{length(@agents)}</div>
          </div>
          <div class="rounded-lg border border-slate-800 bg-slate-900 p-3">
            <div class="text-xs text-slate-500">Total pushes</div>
            <div class="text-2xl font-semibold text-slate-100">{@total_pushes}</div>
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
