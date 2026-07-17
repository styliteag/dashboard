defmodule OrbitWeb.CertificatesLive do
  @moduledoc """
  Fleet certificate expiry — every certificate across the caller's visible
  push instances with its days-remaining verdict, read from the hub
  certificates section. The verdict uses the same cert check family (CRIT
  when expired or <7d, WARN <30d) so it agrees with Alerts and the exports.
  Worst-first, scoped through the instance list (invariant 5); roster PubSub
  + 60s tier timer (certs move slowly).
  """

  use OrbitWeb, :live_view

  alias Orbit.Checks.Evaluate
  alias Orbit.Checks.ServiceCheck
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
      |> Enum.flat_map(fn inst ->
        certs = Hub.cache_entry(inst.id)["certificates"] || []

        for check <- Evaluate.cert_checks(certs) do
          %{instance_id: inst.id, instance_name: inst.name, check: check}
        end
      end)
      |> Enum.sort_by(fn %{check: c, instance_name: n} ->
        {-ServiceCheck.severity(c.state), n, c.key}
      end)

    assign(socket, rows: rows)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:certificates} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Certificates <span class="ml-2 text-sm text-slate-500">({length(@rows)})</span>
        </h1>

        <div :if={@rows == []} class="text-sm text-slate-500">
          No certificates reported in your scope.
        </div>

        <table :if={@rows != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">State</th>
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Certificate</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={r <- @rows} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span class={["rounded px-1.5 py-0.5 text-xs", state_class(r.check.state)]}>
                  {state_label(r.check.state)}
                </span>
              </td>
              <td class="py-2 pr-4">
                <a
                  href={~p"/instances/#{r.instance_id}"}
                  class="text-slate-200 hover:text-emerald-300"
                >
                  {r.instance_name}
                </a>
              </td>
              <td class="py-2 pr-4 text-slate-300">{r.check.summary}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp state_label(0), do: "OK"
  defp state_label(1), do: "EXPIRING"
  defp state_label(2), do: "CRIT"
  defp state_label(_), do: "UNKNOWN"

  defp state_class(0), do: "bg-emerald-900/50 text-emerald-300"
  defp state_class(1), do: "bg-amber-900/50 text-amber-300"
  defp state_class(2), do: "bg-red-900/60 text-red-300"
  defp state_class(_), do: "bg-slate-700 text-slate-300"
end
