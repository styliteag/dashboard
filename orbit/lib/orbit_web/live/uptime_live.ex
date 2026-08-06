defmodule OrbitWeb.UptimeLive do
  @moduledoc """
  /uptime — the fleet availability timeline: every visible instance as one
  lane over a shared 24h/7d/30d window, plus a lean list underneath.

  The instances page answers "what is the fleet doing NOW", the VPN fleet
  graph answers it for tunnels — this page answers "WHEN was each box up":
  did they all drop at 03:12 (a vertical stripe), or does one box flap
  alone? Lanes come from the `availability` check-event history that
  `Orbit.Availability` has been writing all along (offline/online flips,
  ~4 missed pushes debounce), drawn by the same `Checks.History.lane/4`
  the connectivity page uses, so both timelines mean the same thing.

  Clicking a row opens the shared check-history dialog with the recorded
  transitions. Reached from the instances page (no own nav slot — the top
  nav is full).
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.CheckHistoryDialog, only: [check_history_dialog: 1]

  alias Orbit.Auth.Scope
  alias Orbit.Checks.History
  alias Orbit.Instances
  alias OrbitWeb.Components.Icons

  @availability "availability"
  @refresh_ms 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Process.send_after(self(), :refresh, @refresh_ms)

    {:ok,
     socket
     |> assign(page_title: "Uptime", window: "7d", history: nil)
     |> load()}
  end

  @impl true
  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  @impl true
  def handle_event("window", %{"window" => window}, socket) when window in ~w(24h 7d 30d) do
    {:noreply, socket |> assign(window: window) |> load()}
  end

  def handle_event("history_open", %{"iid" => raw_iid}, socket) do
    with {iid, ""} <- Integer.parse(raw_iid),
         inst when not is_nil(inst) <- Scope.get_instance(iid, socket.assigns.current_user),
         row when not is_nil(row) <- Enum.find(socket.assigns.rows, &(&1.id == iid)) do
      {:noreply,
       assign(socket,
         history: %{
           instance_name: inst.name,
           label: "Availability",
           live_state: row.live_state,
           events: History.read(iid, @availability)
         }
       )}
    else
      _ -> {:noreply, socket}
    end
  end

  # The dialog's close button is shared with the connectivity page and
  # emits this event name — keep it.
  def handle_event("monitor_history_close", _params, socket),
    do: {:noreply, assign(socket, history: nil)}

  defp load(socket) do
    now = DateTime.utc_now()
    start = History.window_start(socket.assigns.window, now)

    rows =
      socket.assigns.current_user
      |> Instances.list_visible()
      |> Enum.map(fn inst ->
        %{
          id: inst.id,
          name: inst.name,
          device_type: inst.device_type,
          group: inst.group && inst.group.name,
          transport: inst.transport,
          maintenance: inst.maintenance,
          last_success_at: inst.last_success_at,
          online: Instances.online?(inst),
          live_state: if(Instances.online?(inst), do: 0, else: 2)
        }
      end)
      # Problems first, like the VPN page: an uptime page is opened because
      # something is (or was) down.
      |> Enum.sort_by(&{&1.online, String.downcase(&1.name)})

    events = History.read_many(Enum.map(rows, & &1.id), @availability, start || now)

    lanes =
      Map.new(rows, fn row ->
        lane =
          History.lane(
            Map.get(events, {row.id, @availability}, []),
            row.live_state,
            now,
            start
          )

        {row.id, lane.segments}
      end)

    assign(socket, rows: rows, lanes: lanes)
  end

  defp lane_color(:up), do: "bg-primary"
  defp lane_color(:partial), do: "bg-warning"
  defp lane_color(:down), do: "bg-error"
  defp lane_color(_), do: "bg-neutral"

  @impl true
  def render(assigns) do
    assigns =
      assign(assigns,
        online_count: Enum.count(assigns.rows, & &1.online),
        offline_count: Enum.count(assigns.rows, &(not &1.online))
      )

    ~H"""
    <main id="main" class="min-h-screen bg-base-100 text-base-content">
      <%!-- :uptime matches no nav item on purpose: this page has no nav slot
           yet, and highlighting Instances here misreported where you are
           (UI/UX review U-Q2). --%>
      <.top_nav active={:uptime} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex flex-wrap items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:instances} class="h-5 w-5 text-base-content/60" /> Uptime
            <span class="ml-2 text-sm text-base-content/60">({length(@rows)})</span>
          </h1>
          <a
            href={~p"/instances"}
            class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
          >
            ← Instances
          </a>
          <div class="ml-auto flex items-center gap-1">
            <button
              :for={key <- ~w(24h 7d 30d)}
              phx-click="window"
              phx-value-window={key}
              class={[
                "rounded px-2 py-0.5 text-xs",
                if(@window == key,
                  do: "bg-base-300 text-base-content",
                  else: "text-base-content/60 hover:bg-base-300/60"
                )
              ]}
            >
              {key}
            </button>
          </div>
        </div>

        <div class="mb-4 grid gap-3 sm:grid-cols-3">
          <div class="rounded-lg border border-base-300 bg-base-200 p-3">
            <div class="text-xs text-base-content/60">Total</div>
            <div class="text-xl font-medium">{length(@rows)}</div>
          </div>
          <div class="rounded-lg border border-base-300 bg-base-200 p-3">
            <div class="text-xs text-base-content/60">Online</div>
            <div class="text-xl font-medium text-primary">{@online_count}</div>
          </div>
          <div class="rounded-lg border border-base-300 bg-base-200 p-3">
            <div class="text-xs text-base-content/60">Offline</div>
            <div class="text-xl font-medium text-error">{@offline_count}</div>
          </div>
        </div>

        <%!-- Fleet graph: shared window, one availability lane per box, so a
             fleet-wide event reads as a vertical stripe. --%>
        <div :if={@rows != []} class="mb-4 rounded-lg border border-base-300 bg-base-200 p-4">
          <div :for={row <- @rows} class="mb-1.5">
            <div
              class="flex cursor-pointer items-center gap-2"
              phx-click="history_open"
              phx-value-iid={row.id}
              title="Show recorded transitions"
            >
              <span class="w-44 truncate text-right text-[10px] text-base-content/60">
                {row.name}
              </span>
              <div class="relative h-3.5 flex-1 overflow-hidden rounded bg-base-300">
                <div
                  :for={seg <- @lanes[row.id] || []}
                  class={["absolute h-full", lane_color(seg.state)]}
                  style={"left: #{seg.left}%; width: #{seg.width}%"}
                >
                </div>
              </div>
            </div>
          </div>
          <div class="mt-1 flex justify-between pl-[11.5rem] text-[10px] text-base-content/50">
            <span>{@window} ago</span>
            <span>now</span>
          </div>
        </div>

        <div :if={@rows == []} class="text-sm text-base-content/60">
          No instances visible.
        </div>

        <table :if={@rows != []} class="w-full text-left text-sm">
          <thead class="text-xs text-base-content/60">
            <tr class="border-b border-base-300">
              <th scope="col" class="py-2 pr-3 font-medium">State</th>
              <th scope="col" class="py-2 pr-3 font-medium">Instance</th>
              <th scope="col" class="py-2 pr-3 font-medium">Type</th>
              <th scope="col" class="py-2 pr-3 font-medium">Group</th>
              <th scope="col" class="py-2 pr-3 font-medium">Last seen</th>
              <th scope="col" class="py-2 font-medium">History</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={row <- @rows} class="border-b border-base-300/50 last:border-0">
              <td class="py-2 pr-3">
                <.status
                  state={if row.online, do: :up, else: :down}
                  label={if row.online, do: "online", else: "offline"}
                />
                <span :if={row.maintenance} class="ml-1 text-[10px] text-warning">maint</span>
              </td>
              <td class="py-2 pr-3">
                <.link navigate={~p"/instances/#{row.id}"} class="text-base-content hover:underline">
                  {row.name}
                </.link>
              </td>
              <td class="py-2 pr-3 text-base-content/70">{row.device_type}</td>
              <td class="py-2 pr-3 text-base-content/70">{row.group}</td>
              <td class="py-2 pr-3 text-base-content/70">
                {OrbitWeb.CoreComponents.local_time_tag(row.last_success_at, "datetime-sec")}
              </td>
              <td class="py-2">
                <button
                  phx-click="history_open"
                  phx-value-iid={row.id}
                  class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
                >
                  Timeline
                </button>
              </td>
            </tr>
          </tbody>
        </table>

        <.check_history_dialog history={@history} />
      </section>
    </main>
    """
  end
end
