defmodule OrbitWeb.InstancesLive do
  @moduledoc """
  Instances overview — every firewall the caller may see, with live
  online/agent status. Scoped through Orbit.Instances (invariant 1); the
  agent-connected column reads the hub roster (invariant 5: filtered by the
  same scope the list already applied). Refreshes on hub roster edges + a
  30s tier timer (the standard react refetch tier).
  """

  use OrbitWeb, :live_view

  alias Orbit.Hub
  alias Orbit.Instances

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
    user = socket.assigns.current_user
    connected = Hub.list_connected() |> MapSet.new(& &1.instance_id)

    rows =
      user
      |> Instances.list_visible()
      |> Enum.map(fn inst ->
        %{
          id: inst.id,
          name: inst.name,
          device_type: inst.device_type,
          transport: inst.transport,
          group: inst.group && inst.group.name,
          online: Instances.online?(inst),
          agent_connected: MapSet.member?(connected, inst.id)
        }
      end)

    assign(socket, instances: rows)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <header class="flex items-center justify-between border-b border-slate-800 bg-slate-900 px-6 py-3">
        <div class="flex items-center gap-3">
          <a href={~p"/"} class="font-semibold text-slate-100">STYLiTE Orbit</a>
          <nav class="flex gap-3 text-sm text-slate-400">
            <a href={~p"/instances"} class="text-slate-200">Instances</a>
            <a href={~p"/alerts"} class="hover:text-slate-200">Alerts</a>
            <a href={~p"/hub"} class="hover:text-slate-200">Hub</a>
          </nav>
        </div>
        <span class="text-sm text-slate-400">{@current_user.username}</span>
      </header>

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Instances <span class="ml-2 text-sm text-slate-500">({length(@instances)})</span>
        </h1>

        <div :if={@instances == []} class="text-sm text-slate-500">
          No instances in your scope.
        </div>

        <table :if={@instances != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">Status</th>
              <th class="py-2 pr-4 font-medium">Name</th>
              <th class="py-2 pr-4 font-medium">Type</th>
              <th class="py-2 pr-4 font-medium">Transport</th>
              <th class="py-2 pr-4 font-medium">Group</th>
              <th class="py-2 pr-4 font-medium">Agent</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={i <- @instances} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span
                  class={["inline-block h-2.5 w-2.5 rounded-full", dot(i.online)]}
                  title={status_text(i.online)}
                ></span>
              </td>
              <td class="py-2 pr-4">
                <a href={~p"/instances/#{i.id}"} class="text-slate-200 hover:text-emerald-300">
                  {i.name}
                </a>
              </td>
              <td class="py-2 pr-4 text-slate-400">{i.device_type}</td>
              <td class="py-2 pr-4 text-slate-400">{i.transport}</td>
              <td class="py-2 pr-4 text-slate-400">{i.group || "—"}</td>
              <td class="py-2 pr-4">
                <span :if={i.agent_connected} class="text-emerald-400">connected</span>
                <span :if={not i.agent_connected} class="text-slate-600">—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp dot(true), do: "bg-emerald-500"
  defp dot(false), do: "bg-red-500"

  defp status_text(true), do: "online"
  defp status_text(false), do: "offline"
end
