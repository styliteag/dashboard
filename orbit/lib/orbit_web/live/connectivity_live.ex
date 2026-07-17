defmodule OrbitWeb.ConnectivityLive do
  @moduledoc """
  Fleet connectivity monitors — one row per configured ping monitor across the
  caller's visible push instances, read from the hub `connectivity` section and
  scored by the same connectivity check family (no reply ⇒ CRIT, misconfigured
  ⇒ WARN, 'none' skipped). RTT/loss come straight from the check metrics so the
  page agrees with Alerts and the exports. Worst-first, scoped (invariant 5);
  roster PubSub + 30s tier timer (monitors refresh at push cadence).
  """

  use OrbitWeb, :live_view

  alias Orbit.Checks.Evaluate
  alias Orbit.Checks.ServiceCheck
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
    rows =
      socket.assigns.current_user
      |> Instances.list_visible()
      |> Enum.filter(&Instances.Instance.agent_mode?/1)
      |> Enum.flat_map(fn inst ->
        monitors = Hub.cache_entry(inst.id)["connectivity"] || []

        for check <- Evaluate.connectivity_checks(monitors) do
          %{
            instance_id: inst.id,
            instance_name: inst.name,
            check: check,
            rtt: metric_val(check, "ping_rtt_ms"),
            loss: metric_val(check, "ping_loss_pct")
          }
        end
      end)
      |> Enum.sort_by(fn %{check: c, instance_name: n} ->
        {-ServiceCheck.severity(c.state), n, c.key}
      end)

    assign(socket, rows: rows)
  end

  defp metric_val(%ServiceCheck{metrics: metrics}, name) do
    case Enum.find(metrics, &(&1.name == name)) do
      %{value: v} when is_number(v) -> v
      _ -> nil
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:connectivity} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          Connectivity monitors <span class="ml-2 text-sm text-slate-500">({length(@rows)})</span>
        </h1>

        <div :if={@rows == []} class="text-sm text-slate-500">
          No connectivity monitors reported in your scope.
        </div>

        <table :if={@rows != []} class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">State</th>
              <th class="py-2 pr-4 font-medium">Instance</th>
              <th class="py-2 pr-4 font-medium">Monitor</th>
              <th class="py-2 pr-4 text-right font-medium">RTT</th>
              <th class="py-2 pr-4 text-right font-medium">Loss</th>
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
              <td class="py-2 pr-4 text-right text-slate-400">{rtt_text(r.rtt)}</td>
              <td class="py-2 pr-4 text-right text-slate-400">{loss_text(r.loss)}</td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp rtt_text(nil), do: "—"
  defp rtt_text(v) when is_number(v), do: "#{Float.round(v / 1, 1)} ms"

  defp loss_text(nil), do: "—"
  defp loss_text(v) when is_number(v), do: "#{Float.round(v / 1, 0)}%"

  defp state_label(0), do: "OK"
  defp state_label(1), do: "WARN"
  defp state_label(2), do: "CRIT"
  defp state_label(_), do: "UNKNOWN"

  defp state_class(0), do: "bg-emerald-900/50 text-emerald-300"
  defp state_class(1), do: "bg-amber-900/50 text-amber-300"
  defp state_class(2), do: "bg-red-900/60 text-red-300"
  defp state_class(_), do: "bg-slate-700 text-slate-300"
end
