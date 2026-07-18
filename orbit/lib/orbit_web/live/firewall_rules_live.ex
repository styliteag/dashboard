defmodule OrbitWeb.FirewallRulesLive do
  @moduledoc """
  Firewall-rules management for one OPNsense instance (FirewallRulesSection
  parity) — list rules per interface, toggle/delete, apply staged changes.
  Write-gated; scoped via get_instance (invariant 1). Rule reads/writes
  relay through Orbit.Firewall (agent http.relay or direct API). Only
  OPNsense device types; non-OPNsense or non-agent-without-creds surface a
  readable message instead of the table.
  """

  use OrbitWeb, :live_view

  alias Orbit.Auth.Scope
  alias Orbit.Firewall

  @write_roles ~w(admin user)

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with true <- user.role in @write_roles,
         {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user),
         true <- Firewall.supported?(inst) do
      socket =
        socket
        |> assign(instance: inst, error: nil, flash_msg: nil, interfaces: [], interface: nil)
        |> load_interfaces()
        |> load_rules()

      {:ok, socket}
    else
      false -> {:ok, push_navigate(socket, to: ~p"/instances")}
      _ -> {:ok, push_navigate(socket, to: ~p"/instances")}
    end
  end

  defp load_interfaces(socket) do
    ifaces = Firewall.interfaces(socket.assigns.instance)
    current = socket.assigns.interface || (List.first(ifaces) || %{})[:value]
    assign(socket, interfaces: ifaces, interface: current)
  end

  defp load_rules(socket) do
    case Firewall.search_rules(socket.assigns.instance, interface: socket.assigns.interface) do
      {:ok, %{rows: rows}} -> assign(socket, rules: rows, error: nil)
      {:error, msg} -> assign(socket, rules: [], error: msg)
    end
  end

  @impl true
  def handle_event("select_interface", %{"interface" => iface}, socket) do
    {:noreply, socket |> assign(interface: iface) |> load_rules()}
  end

  def handle_event("toggle", %{"uuid" => uuid, "enabled" => enabled}, socket) do
    # enabled is the CURRENT state; toggle to the opposite.
    run(socket, fn inst ->
      Firewall.toggle_rule(inst, uuid, enabled != "true", user_id: socket.assigns.current_user.id)
    end)
  end

  def handle_event("delete", %{"uuid" => uuid}, socket) do
    run(socket, fn inst ->
      Firewall.delete_rule(inst, uuid, user_id: socket.assigns.current_user.id)
    end)
  end

  def handle_event("apply", _params, socket) do
    case Firewall.apply(socket.assigns.instance, user_id: socket.assigns.current_user.id) do
      {:ok, _} -> {:noreply, assign(socket, flash_msg: "Changes applied.", error: nil)}
      {:error, msg} -> {:noreply, assign(socket, error: msg)}
    end
  end

  defp run(socket, fun) do
    case fun.(socket.assigns.instance) do
      {:ok, _} ->
        {:noreply, socket |> assign(flash_msg: "Saved — apply to activate.") |> load_rules()}

      {:error, msg} ->
        {:noreply, assign(socket, error: msg)}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex flex-wrap items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">Firewall rules — {@instance.name}</h1>
          <a href={~p"/instances/#{@instance.id}"} class="text-xs text-slate-500 hover:text-slate-300">
            back to detail
          </a>
          <form phx-change="select_interface">
            <select
              name="interface"
              class="rounded border border-slate-700 bg-slate-950 p-1 text-sm text-slate-200"
            >
              <option :for={i <- @interfaces} value={i.value} selected={i.value == @interface}>
                {i.label}
              </option>
            </select>
          </form>
          <button
            phx-click="apply"
            data-confirm="Apply staged firewall changes on the box?"
            class="rounded bg-amber-700 px-3 py-1 text-xs text-white hover:bg-amber-600"
          >
            Apply changes
          </button>
        </div>

        <div
          :if={@flash_msg}
          class="mb-3 rounded border border-emerald-800 bg-emerald-950/40 p-2 text-sm text-emerald-300"
        >
          {@flash_msg}
        </div>
        <div
          :if={@error}
          class="mb-3 rounded border border-red-800 bg-red-950/50 p-2 text-sm text-red-300"
        >
          {@error}
        </div>

        <table class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-3 font-medium">On</th>
              <th class="py-2 pr-3 font-medium">Action</th>
              <th class="py-2 pr-3 font-medium">Proto</th>
              <th class="py-2 pr-3 font-medium">Source</th>
              <th class="py-2 pr-3 font-medium">Destination</th>
              <th class="py-2 pr-3 font-medium">Description</th>
              <th class="py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <tr :for={r <- @rules} class="border-b border-slate-800/50">
              <td class="py-1.5 pr-3">
                <button
                  :if={r.editable}
                  phx-click="toggle"
                  phx-value-uuid={r.uuid}
                  phx-value-enabled={to_string(r.enabled)}
                  class={[
                    "rounded px-1.5 py-0.5 text-xs",
                    if(r.enabled,
                      do: "bg-emerald-900/50 text-emerald-300",
                      else: "bg-slate-700 text-slate-400"
                    )
                  ]}
                >
                  {if r.enabled, do: "on", else: "off"}
                </button>
                <span :if={not r.editable} class="text-xs text-slate-600">
                  {if r.enabled, do: "on", else: "off"}
                </span>
              </td>
              <td class="py-1.5 pr-3 text-slate-300">{r.action}</td>
              <td class="py-1.5 pr-3 text-slate-400">{r.protocol}</td>
              <td class="py-1.5 pr-3 font-mono text-xs text-slate-400">
                {r.source}{if r.source_port != "", do: ":#{r.source_port}"}
              </td>
              <td class="py-1.5 pr-3 font-mono text-xs text-slate-400">
                {r.destination}{if r.destination_port != "", do: ":#{r.destination_port}"}
              </td>
              <td class="py-1.5 pr-3 text-slate-300">{r.description}</td>
              <td class="py-1.5 text-right">
                <button
                  :if={r.editable}
                  phx-click="delete"
                  phx-value-uuid={r.uuid}
                  data-confirm="Delete this rule? (apply to activate)"
                  class="rounded border border-red-900 px-2 py-0.5 text-xs text-red-400 hover:bg-red-950"
                >
                  delete
                </button>
                <span :if={not r.editable} class="text-xs text-slate-600">legacy</span>
              </td>
            </tr>
          </tbody>
        </table>
        <div :if={@rules == [] and is_nil(@error)} class="py-4 text-sm text-slate-500">
          No rules on this interface.
        </div>
      </section>
    </main>
    """
  end
end
