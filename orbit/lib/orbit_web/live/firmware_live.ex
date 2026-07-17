defmodule OrbitWeb.FirmwareLive do
  @moduledoc """
  Fleet firmware compliance — current version + pending-update state per
  visible instance, read from the hub section cache (raw firmware section).
  The update verdict uses the same firmware check family (security ⇒ WARN,
  routine ⇒ ok-but-counted, failed check ⇒ WARN), so it agrees with Alerts
  and the exports. Scoped through the instance list (invariant 5); roster-edge
  PubSub + 60s tier timer (firmware moves slowly).
  """

  use OrbitWeb, :live_view

  alias Orbit.Checks.Evaluate
  alias Orbit.Hub
  alias Orbit.Instances

  @refresh_ms 60_000

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
    rows =
      socket.assigns.current_user
      |> Instances.list_visible()
      |> Enum.filter(&Instances.Instance.agent_mode?/1)
      |> Enum.map(fn inst ->
        fw = Hub.cache_entry(inst.id)["firmware"]
        check = fw && Evaluate.firmware_check(fw)

        %{
          id: inst.id,
          name: inst.name,
          version: (fw && fw["product_version"]) || "—",
          state: (check && check.state) || 3,
          summary: (check && check.summary) || "No firmware data"
        }
      end)
      |> Enum.sort_by(&{-Orbit.Checks.ServiceCheck.severity(&1.state), &1.name})

    assign(socket, rows: rows)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:firmware} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Firmware <span class="ml-2 text-sm text-slate-500">({length(@rows)})</span>
        </h1>

        <div :if={@rows == []} class="text-sm text-slate-500">
          No push instances in your scope.
        </div>

        <table :if={@rows != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">State</th>
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Version</th>
              <th class="py-2 pr-4 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={r <- @rows} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span class={["rounded px-1.5 py-0.5 text-xs", state_class(r.state)]}>
                  {state_label(r.state)}
                </span>
              </td>
              <td class="py-2 pr-4">
                <a href={~p"/instances/#{r.id}"} class="text-slate-200 hover:text-emerald-300">
                  {r.name}
                </a>
              </td>
              <td class="py-2 pr-4 font-mono text-xs text-slate-400">{r.version}</td>
              <td class="py-2 pr-4 text-slate-300">{r.summary}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp state_label(0), do: "OK"
  defp state_label(1), do: "UPDATE"
  defp state_label(2), do: "CRIT"
  defp state_label(_), do: "UNKNOWN"

  defp state_class(0), do: "bg-emerald-900/50 text-emerald-300"
  defp state_class(1), do: "bg-amber-900/50 text-amber-300"
  defp state_class(2), do: "bg-red-900/60 text-red-300"
  defp state_class(_), do: "bg-slate-700 text-slate-300"
end
