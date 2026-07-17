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

  # Scope the unscoped hub roster: keep only instances the user may see, then
  # decorate each with its live cpu from the section cache.
  defp visible_agents(user) do
    Hub.list_connected()
    |> Enum.filter(&(Scope.get_instance(&1.instance_id, user) != nil))
    |> Enum.sort_by(& &1.instance_id)
    |> Enum.map(fn agent ->
      cpu =
        Hub.cache_entry(agent.instance_id)
        |> get_in(["status", "cpu", "total"])

      %{
        instance_id: agent.instance_id,
        version: agent.agent_version,
        platform: agent.platform,
        pushes: agent.pushes,
        last_push_at: agent.last_push_at,
        cpu: cpu,
        update_error: agent.last_update_error
      }
    end)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <header class="flex items-center justify-between border-b border-slate-800 bg-slate-900 px-6 py-3">
        <div class="flex items-center gap-3">
          <a href={~p"/"} class="font-semibold text-slate-100">STYLiTE Orbit</a>
          <span class="rounded bg-emerald-900/50 px-2 py-0.5 text-xs text-emerald-300">live</span>
        </div>
        <span class="text-sm text-slate-400">{@current_user.username}</span>
      </header>

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Connected agents <span class="ml-2 text-sm text-slate-500">({length(@agents)})</span>
        </h1>

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
              <th class="py-2 pr-4 font-medium">Last push</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={a <- @agents} class="border-b border-slate-800/50">
              <td class="py-2 pr-4 text-slate-200">{"##{a.instance_id}"}</td>
              <td class="py-2 pr-4 text-slate-400">{a.platform}</td>
              <td class="py-2 pr-4 text-slate-400">
                {a.version}
                <span :if={a.update_error} class="ml-1 text-amber-400" title={a.update_error}>
                  ⚠
                </span>
              </td>
              <td class="py-2 pr-4 text-slate-300">{cpu_text(a.cpu)}</td>
              <td class="py-2 pr-4 text-slate-400">{a.pushes}</td>
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
