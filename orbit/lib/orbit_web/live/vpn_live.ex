defmodule OrbitWeb.VpnLive do
  @moduledoc """
  Fleet IPsec overview — every configured tunnel across the caller's visible
  push instances, with live up/down state read from the hub section cache
  (raw ipsec section: %{"running", "tunnels" => [...]}). Scoped through the
  instance list (invariant 5). Refreshes on hub roster edges + a 30s tier
  timer.

  Read-only view; the per-tunnel up/down verdict matches the ipsec check
  family (_ipsec_up set) so it agrees with Alerts and the exports.
  """

  use OrbitWeb, :live_view

  alias Orbit.Hub
  alias Orbit.Instances

  @refresh_ms 30_000
  @ipsec_up ~w(established installed connected up 1 true yes)

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
    tunnels =
      socket.assigns.current_user
      |> Instances.list_visible()
      |> Enum.filter(&Instances.Instance.agent_mode?/1)
      |> Enum.flat_map(fn inst ->
        ipsec = Hub.cache_entry(inst.id)["ipsec"] || %{}

        for t <- ipsec["tunnels"] || [] do
          status = (t["status"] || "") |> to_string() |> String.downcase()

          %{
            instance_id: inst.id,
            instance_name: inst.name,
            label: t["description"] || t["id"] || "tunnel",
            status: t["status"] || "?",
            up: status in @ipsec_up,
            remote: t["remote"] || ""
          }
        end
      end)
      |> Enum.sort_by(&{not &1.up, &1.instance_name, &1.label})

    assign(socket, tunnels: tunnels)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:vpn} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          IPsec tunnels <span class="ml-2 text-sm text-slate-500">({length(@tunnels)})</span>
        </h1>

        <div :if={@tunnels == []} class="text-sm text-slate-500">
          No IPsec tunnels reported in your scope.
        </div>

        <table :if={@tunnels != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">State</th>
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Tunnel</th>
              <th class="py-2 pr-4 font-medium">Remote</th>
              <th class="py-2 pr-4 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={t <- @tunnels} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span class={[
                  "inline-block h-2.5 w-2.5 rounded-full",
                  if(t.up, do: "bg-emerald-500", else: "bg-red-500")
                ]}></span>
              </td>
              <td class="py-2 pr-4">
                <a
                  href={~p"/instances/#{t.instance_id}"}
                  class="text-slate-200 hover:text-emerald-300"
                >
                  {t.instance_name}
                </a>
              </td>
              <td class="py-2 pr-4 text-slate-300">{t.label}</td>
              <td class="py-2 pr-4 text-slate-500">{t.remote}</td>
              <td class="py-2 pr-4 text-slate-400">{t.status}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end
end
