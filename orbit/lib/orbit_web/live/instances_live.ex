defmodule OrbitWeb.InstancesLive do
  @moduledoc """
  Instances overview — every firewall the caller may see, with live
  online/agent status. Scoped through Orbit.Instances (invariant 1); the
  agent-connected column reads the hub roster (invariant 5: filtered by the
  same scope the list already applied). Refreshes on hub roster edges + a
  30s tier timer (the standard react refetch tier).

  Bulk actions (bulk/routes.py port): row checkboxes + an action bar for
  write roles. The handler re-checks the write gate (never trust hidden
  UI); ids outside the caller's scope are silently dropped in Orbit.Bulk.
  Actions run in start_async (firmware_check blocks up to 90s per box).
  CSV export is a sanctioned <a href> download.
  """

  use OrbitWeb, :live_view

  alias Orbit.Bulk
  alias Orbit.Hub
  alias Orbit.Instances

  @refresh_ms 30_000
  @write_roles ~w(admin user)

  @bulk_actions [
    {"firmware_check", "Check updates"},
    {"firmware_update", "Update firmware"},
    {"ipsec_restart", "Restart IPsec"},
    {"reboot", "Reboot"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
      Process.send_after(self(), :refresh, @refresh_ms)
    end

    socket =
      assign(socket,
        writable: socket.assigns.current_user.role in @write_roles,
        selected: MapSet.new(),
        bulk_busy: false,
        bulk_results: nil
      )

    {:ok, load(socket)}
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  @impl true
  def handle_event("toggle_select", %{"id" => raw_id}, socket) do
    {id, ""} = Integer.parse(raw_id)
    selected = socket.assigns.selected

    selected =
      if MapSet.member?(selected, id),
        do: MapSet.delete(selected, id),
        else: MapSet.put(selected, id)

    {:noreply, assign(socket, selected: selected)}
  end

  def handle_event("select_all", _params, socket) do
    all = MapSet.new(socket.assigns.instances, & &1.id)

    selected =
      if MapSet.equal?(socket.assigns.selected, all), do: MapSet.new(), else: all

    {:noreply, assign(socket, selected: selected)}
  end

  def handle_event("bulk", %{"action" => action}, socket) do
    cond do
      not socket.assigns.writable ->
        {:noreply, socket}

      socket.assigns.bulk_busy or MapSet.size(socket.assigns.selected) == 0 ->
        {:noreply, socket}

      true ->
        ids = MapSet.to_list(socket.assigns.selected)
        user = socket.assigns.current_user

        {:noreply,
         socket
         |> assign(bulk_busy: true, bulk_results: nil)
         |> start_async(:bulk, fn -> Bulk.run(ids, action, user) end)}
    end
  end

  def handle_event("clear_results", _params, socket) do
    {:noreply, assign(socket, bulk_results: nil)}
  end

  @impl true
  def handle_async(:bulk, {:ok, {:ok, results}}, socket) do
    {:noreply, assign(socket, bulk_busy: false, bulk_results: results)}
  end

  def handle_async(:bulk, {:ok, {:error, :unknown_action}}, socket) do
    {:noreply, assign(socket, bulk_busy: false, bulk_results: [])}
  end

  def handle_async(:bulk, {:exit, _reason}, socket) do
    {:noreply, assign(socket, bulk_busy: false, bulk_results: [])}
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
    assigns = Phoenix.Component.assign(assigns, :bulk_actions, @bulk_actions)

    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex flex-wrap items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">
            Instances <span class="ml-2 text-sm text-slate-500">({length(@instances)})</span>
          </h1>
          <a
            href={~p"/api/export/instances.csv"}
            class="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
          >
            Export CSV
          </a>
          <div :if={@writable and MapSet.size(@selected) > 0} class="flex items-center gap-2">
            <span class="text-xs text-slate-500">{MapSet.size(@selected)} selected:</span>
            <button
              :for={{action, label} <- @bulk_actions}
              phx-click="bulk"
              phx-value-action={action}
              data-confirm={"#{label} on #{MapSet.size(@selected)} instance(s)?"}
              disabled={@bulk_busy}
              class="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @bulk_busy, do: "Running…", else: label}
            </button>
          </div>
        </div>

        <div
          :if={@bulk_results}
          class="mb-4 rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm"
        >
          <div class="mb-2 flex items-center gap-3">
            <span class="text-slate-300">
              Bulk result: {Enum.count(@bulk_results, & &1.success)} ok, {Enum.count(
                @bulk_results,
                &(not &1.success)
              )} failed
            </span>
            <button phx-click="clear_results" class="text-xs text-slate-500 hover:text-slate-300">
              dismiss
            </button>
          </div>
          <div :for={r <- @bulk_results} class="text-xs">
            <span class={if r.success, do: "text-emerald-400", else: "text-red-400"}>
              {r.instance_name}
            </span>
            <span class="text-slate-500"> — {r.message}</span>
          </div>
        </div>

        <div :if={@instances == []} class="text-sm text-slate-500">
          No instances in your scope.
        </div>

        <table :if={@instances != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th :if={@writable} class="py-2 pr-3">
                <input
                  type="checkbox"
                  phx-click="select_all"
                  checked={MapSet.size(@selected) == length(@instances)}
                  class="accent-emerald-600"
                />
              </th>
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
              <td :if={@writable} class="py-2 pr-3">
                <input
                  type="checkbox"
                  phx-click="toggle_select"
                  phx-value-id={i.id}
                  checked={MapSet.member?(@selected, i.id)}
                  class="accent-emerald-600"
                />
              </td>
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
