defmodule OrbitWeb.VpnLive do
  @moduledoc """
  Fleet IPsec overview — every configured tunnel across the caller's visible
  push instances, with live up/down state read from the hub section cache
  (raw ipsec section: %{"running", "tunnels" => [...]}). Scoped through the
  instance list (invariant 5). Refreshes on hub roster edges + a 30s tier
  timer.

  The per-tunnel up/down verdict matches the ipsec check family (_ipsec_up
  set) so it agrees with Alerts and the exports. Interaction parity with
  VPNOverviewPage.tsx: KPI tiles as up/down filters, search, sortable
  columns, phase-2/uptime/traffic columns, reconnect per row (agent relay)
  and WebUI/Terminal quick links.
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit

  alias Orbit.Audit
  alias Orbit.Auth.Scope
  alias Orbit.Hub
  alias Orbit.Instances

  @refresh_ms 30_000
  @ipsec_up ~w(established installed connected up 1 true yes)
  @write_roles ~w(admin user)
  @sort_cols ~w(state instance tunnel remote uptime)

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
      Process.send_after(self(), :refresh, @refresh_ms)
    end

    {:ok,
     socket
     |> assign(
       search: "",
       state_filter: "all",
       sort_col: "state",
       sort_dir: :asc,
       busy: MapSet.new(),
       msg: nil,
       writable: socket.assigns.current_user.role in @write_roles
     )
     |> load()}
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  @impl true
  def handle_event("search", %{"q" => q}, socket), do: {:noreply, assign(socket, search: q)}

  def handle_event("state_filter", %{"bucket" => b}, socket) when b in ~w(all up down) do
    b = if socket.assigns.state_filter == b, do: "all", else: b
    {:noreply, assign(socket, state_filter: b)}
  end

  def handle_event("sort", %{"col" => col}, socket) when col in @sort_cols do
    dir =
      if socket.assigns.sort_col == col and socket.assigns.sort_dir == :asc,
        do: :desc,
        else: :asc

    {:noreply, assign(socket, sort_col: col, sort_dir: dir)}
  end

  def handle_event("row_gui_open", %{"id" => id}, socket) do
    {:noreply, gui_open_row(socket, id)}
  end

  # Fleet-row reconnect: same relay pair as the detail page. The instance id
  # from the DOM re-resolves through scope (invariant 1).
  def handle_event("reconnect", %{"iid" => iid, "id" => id, "uid" => uid}, socket) do
    key = "#{iid}:#{id}"

    with true <- socket.assigns.writable and not MapSet.member?(socket.assigns.busy, key),
         {nid, ""} <- Integer.parse(iid),
         inst when not is_nil(inst) <- Scope.get_instance(nid, socket.assigns.current_user) do
      user = socket.assigns.current_user

      {:noreply,
       socket
       |> assign(busy: MapSet.put(socket.assigns.busy, key))
       |> start_async({:reconnect, key}, fn ->
         if uid != "",
           do: Hub.send_command(inst.id, "ipsec.disconnect", %{"tunnel_id" => uid}, 30_000)

         result = Hub.send_command(inst.id, "ipsec.connect", %{"tunnel_id" => id}, 30_000)
         result = if is_map(result), do: result, else: %{"success" => false}

         Audit.write(
           action: "ipsec.connect",
           result: if(result["success"], do: "ok", else: "error"),
           user_id: user.id,
           target_type: "instance",
           target_id: inst.id
         )

         if result["success"],
           do: {:ok, "#{inst.name}: tunnel #{id} initiated"},
           else: {:error, to_string(result["output"] || "connect failed")}
       end)}
    else
      _ -> {:noreply, socket}
    end
  end

  @impl true
  def handle_async({:reconnect, key}, {:ok, outcome}, socket) do
    {:noreply,
     socket
     |> assign(busy: MapSet.delete(socket.assigns.busy, key), msg: outcome)
     |> load()}
  end

  def handle_async({:reconnect, key}, {:exit, _}, socket) do
    {:noreply,
     assign(socket,
       busy: MapSet.delete(socket.assigns.busy, key),
       msg: {:error, "action crashed"}
     )}
  end

  defp load(socket) do
    tunnels =
      socket.assigns.current_user
      |> Instances.list_visible()
      |> Enum.filter(&Instances.Instance.agent_mode?/1)
      |> Enum.flat_map(fn inst ->
        ipsec = Hub.cache_entry(inst.id)["ipsec"] || %{}
        gui_openable = Orbit.GUI.openable(inst) == :ok

        for t <- ipsec["tunnels"] || [] do
          status = (t["status"] || "") |> to_string() |> String.downcase()

          %{
            instance_id: inst.id,
            instance_name: inst.name,
            shell_enabled: inst.shell_enabled,
            gui_openable: gui_openable,
            id: to_string(t["id"] || t["description"] || "tunnel"),
            unique_id: to_string(t["unique_id"] || ""),
            label: t["description"] || t["id"] || "tunnel",
            status: t["status"] || "?",
            up: status in @ipsec_up,
            remote: t["remote"] || "",
            phase2_up: int0(t["phase2_up"]),
            phase2_total: int0(t["phase2_total"]),
            uptime_s: int0(t["seconds_established"]),
            bytes_in: int0(t["bytes_in"]),
            bytes_out: int0(t["bytes_out"])
          }
        end
      end)

    assign(socket, tunnels: tunnels)
  end

  defp visible(a) do
    q = String.downcase(a.search)

    a.tunnels
    |> Enum.filter(fn t ->
      q == "" or
        String.contains?(String.downcase(t.instance_name), q) or
        String.contains?(String.downcase(to_string(t.label)), q) or
        String.contains?(String.downcase(t.remote), q)
    end)
    |> Enum.filter(fn t ->
      case a.state_filter do
        "all" -> true
        "up" -> t.up
        "down" -> not t.up
      end
    end)
    |> Enum.sort_by(sort_key(a.sort_col), a.sort_dir)
  end

  defp sort_key("state"), do: fn t -> {t.up, String.downcase(t.instance_name)} end
  defp sort_key("instance"), do: fn t -> String.downcase(t.instance_name) end
  defp sort_key("tunnel"), do: fn t -> String.downcase(to_string(t.label)) end
  defp sort_key("remote"), do: fn t -> t.remote end
  defp sort_key("uptime"), do: fn t -> t.uptime_s end

  @impl true
  def render(assigns) do
    assigns =
      assign(assigns,
        rows: visible(assigns),
        up_count: Enum.count(assigns.tunnels, & &1.up),
        down_count: Enum.count(assigns.tunnels, &(not &1.up))
      )

    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:vpn} current_user={@current_user} />

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">
          IPsec tunnels <span class="ml-2 text-sm text-slate-500">({length(@tunnels)})</span>
        </h1>

        <div class="mb-4 grid gap-3 sm:grid-cols-3">
          <.kpi_tile
            label="Total"
            value={length(@tunnels)}
            event="state_filter"
            value_name="all"
            active={@state_filter == "all"}
          />
          <.kpi_tile
            label="Up"
            value={@up_count}
            color="text-emerald-400"
            event="state_filter"
            value_name="up"
            active={@state_filter == "up"}
          />
          <.kpi_tile
            label="Down"
            value={@down_count}
            color="text-red-400"
            event="state_filter"
            value_name="down"
            active={@state_filter == "down"}
          />
        </div>

        <form phx-change="search" onsubmit="return false" class="mb-3 max-w-md">
          <input
            type="text"
            name="q"
            value={@search}
            placeholder="Search instance, tunnel, remote…"
            phx-debounce="300"
            class="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm focus:border-emerald-600 focus:outline-none focus:ring-1 focus:ring-emerald-600"
          />
        </form>

        <div
          :if={@msg}
          class={[
            "mb-3 rounded px-3 py-2 text-xs",
            case @msg do
              {:ok, _} -> "bg-emerald-900/40 text-emerald-300"
              _ -> "bg-red-900/40 text-red-300"
            end
          ]}
        >
          {elem(@msg, 1)}
        </div>

        <div :if={@tunnels == []} class="text-sm text-slate-500">
          No IPsec tunnels reported in your scope.
        </div>
        <div :if={@tunnels != [] and @rows == []} class="text-sm text-slate-500">No matches.</div>

        <div :if={@rows != []} class="overflow-x-auto rounded-lg border border-slate-800">
          <table class="w-full text-left text-sm">
            <thead class="bg-slate-900 text-xs text-slate-500">
              <tr>
                <.sort_th col="state" label="State" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="instance" label="Instance" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="tunnel" label="Tunnel" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="remote" label="Remote" sort_col={@sort_col} sort_dir={@sort_dir} />
                <th class="px-3 py-2 font-medium">Phase 2</th>
                <.sort_th col="uptime" label="Uptime" sort_col={@sort_col} sort_dir={@sort_dir} />
                <th class="px-3 py-2 font-medium">In / Out</th>
                <th :if={@writable} class="px-3 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={t <- @rows} class="border-b border-slate-800/50 last:border-0">
                <td class="px-3 py-2">
                  <span class={[
                    "inline-block h-2.5 w-2.5 rounded-full",
                    if(t.up, do: "bg-emerald-500", else: "bg-red-500")
                  ]}></span>
                </td>
                <td class="px-3 py-2">
                  <a
                    href={~p"/instances/#{t.instance_id}"}
                    class="text-slate-200 hover:text-emerald-300"
                  >
                    {t.instance_name}
                  </a>
                  <.webui_link instance_id={t.instance_id} openable={t.gui_openable} />
                  <.shell_link instance_id={t.instance_id} shell_enabled={t.shell_enabled} />
                </td>
                <td class="px-3 py-2 text-slate-300">{t.label}</td>
                <td class="px-3 py-2 text-slate-500">{t.remote}</td>
                <td class="px-3 py-2 text-slate-400">
                  <span :if={t.phase2_total > 0}>{t.phase2_up}/{t.phase2_total} up</span>
                  <span :if={t.phase2_total == 0}>—</span>
                </td>
                <td class="px-3 py-2 text-slate-400">{duration(t.uptime_s)}</td>
                <td class="px-3 py-2 text-slate-400">{bytes(t.bytes_in)} / {bytes(t.bytes_out)}</td>
                <td :if={@writable} class="px-3 py-2 text-right text-xs">
                  <button
                    phx-click="reconnect"
                    phx-value-iid={t.instance_id}
                    phx-value-id={t.id}
                    phx-value-uid={t.unique_id}
                    disabled={MapSet.member?(@busy, "#{t.instance_id}:#{t.id}")}
                    class="rounded border border-slate-700 px-2 py-0.5 text-slate-300 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {if MapSet.member?(@busy, "#{t.instance_id}:#{t.id}"),
                      do: "…",
                      else: "Reconnect"}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>
    """
  end

  defp int0(v) when is_number(v), do: trunc(v)
  defp int0(_), do: 0

  defp duration(s) when is_integer(s) and s > 0 do
    cond do
      s >= 86_400 -> "#{div(s, 86_400)}d #{div(rem(s, 86_400), 3_600)}h"
      s >= 3_600 -> "#{div(s, 3_600)}h #{div(rem(s, 3_600), 60)}m"
      s >= 60 -> "#{div(s, 60)}m"
      true -> "#{s}s"
    end
  end

  defp duration(_), do: "—"

  defp bytes(n) when is_integer(n) and n > 0 do
    cond do
      n >= 1_073_741_824 -> "#{Float.round(n / 1_073_741_824, 1)} GB"
      n >= 1_048_576 -> "#{Float.round(n / 1_048_576, 1)} MB"
      n >= 1_024 -> "#{Float.round(n / 1_024, 1)} KB"
      true -> "#{n} B"
    end
  end

  defp bytes(_), do: "0 B"
end
