defmodule OrbitWeb.FirewallRulesLive do
  @moduledoc """
  Firewall-rules management for one OPNsense instance (FirewallRulesSection
  parity) — list rules per interface, search, toggle/delete, move up/down,
  clone, full create/edit form, apply staged changes. Write-gated; scoped
  via get_instance (invariant 1). Rule reads/writes relay through
  Orbit.Firewall (agent http.relay or direct API). Only OPNsense device
  types; non-OPNsense or non-agent-without-creds surface a readable message
  instead of the table.
  """

  use OrbitWeb, :live_view

  alias Orbit.Auth.Scope
  alias Orbit.Firewall

  @write_roles ~w(admin user)

  # Editor field set — the exact OPNsense set_rule/add_rule payload keys.
  @editor_fields ~w(enabled action interface direction ipprotocol protocol
    source_net source_port destination_net destination_port description log quick)

  @impl true
  def mount(%{"id" => raw_id}, _session, socket) do
    user = socket.assigns.current_user

    with true <- user.role in @write_roles,
         {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user),
         true <- Firewall.supported?(inst) do
      socket =
        socket
        |> assign(
          instance: inst,
          error: nil,
          flash_msg: nil,
          interfaces: [],
          interface: nil,
          search: "",
          editor: nil,
          editor_uuid: nil,
          busy: false
        )
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

  def handle_event("search", %{"q" => q}, socket) do
    {:noreply, assign(socket, search: q)}
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

  # Reorder: move the selected rule directly before its visual neighbour
  # (move_rule_before, FirewallRulesSection arrows).
  def handle_event("move_before", %{"uuid" => uuid, "target" => target}, socket)
      when target != "" do
    run(socket, fn inst ->
      Firewall.move_rule(inst, uuid, target, user_id: socket.assigns.current_user.id)
    end)
  end

  def handle_event("move_before", _params, socket), do: {:noreply, socket}

  def handle_event("apply", _params, socket) do
    case Firewall.apply(socket.assigns.instance, user_id: socket.assigns.current_user.id) do
      {:ok, _} -> {:noreply, assign(socket, flash_msg: "Changes applied.", error: nil)}
      {:error, msg} -> {:noreply, assign(socket, error: msg)}
    end
  end

  # ---- editor ---------------------------------------------------------------

  def handle_event("new_rule", _params, socket) do
    editor = %{
      "enabled" => "1",
      "action" => "pass",
      "interface" => socket.assigns.interface || "",
      "direction" => "in",
      "ipprotocol" => "inet",
      "protocol" => "any",
      "source_net" => "any",
      "source_port" => "",
      "destination_net" => "any",
      "destination_port" => "",
      "description" => "",
      "log" => "0",
      "quick" => "1"
    }

    {:noreply, assign(socket, editor: editor, editor_uuid: nil, error: nil)}
  end

  def handle_event("edit_rule", %{"uuid" => uuid}, socket) do
    open_editor(socket, uuid, uuid)
  end

  # Clone = load the source rule's fields, save as NEW (uuid nil).
  def handle_event("clone_rule", %{"uuid" => uuid}, socket) do
    open_editor(socket, uuid, nil)
  end

  def handle_event("cancel_editor", _params, socket) do
    {:noreply, assign(socket, editor: nil, editor_uuid: nil)}
  end

  def handle_event("save_rule", %{"rule" => params}, socket) do
    fields =
      @editor_fields
      |> Map.new(fn key -> {key, Map.get(params, key, "")} end)
      |> Map.update!("enabled", &checkbox/1)
      |> Map.update!("log", &checkbox/1)
      |> Map.update!("quick", &checkbox/1)

    case Firewall.save_rule(
           socket.assigns.instance,
           socket.assigns.editor_uuid,
           fields,
           user_id: socket.assigns.current_user.id
         ) do
      {:ok, _} ->
        {:noreply,
         socket
         |> assign(editor: nil, editor_uuid: nil, flash_msg: "Saved — apply to activate.")
         |> load_rules()}

      {:error, msg} ->
        {:noreply, assign(socket, error: msg)}
    end
  end

  defp open_editor(socket, source_uuid, editor_uuid) do
    case Firewall.get_rule(socket.assigns.instance, source_uuid) do
      {:ok, rule} ->
        editor = Map.new(@editor_fields, fn key -> {key, editor_value(rule, key)} end)
        {:noreply, assign(socket, editor: editor, editor_uuid: editor_uuid, error: nil)}

      {:error, msg} ->
        {:noreply, assign(socket, error: msg)}
    end
  end

  # get_rule returns the raw OPNsense field set: scalars or option maps
  # ({value => %{"selected" => 1, ...}}). Reduce each to the editor's string.
  defp editor_value(rule, key) do
    case rule[key] do
      nil ->
        ""

      %{} = options ->
        Enum.find_value(options, "", fn {value, item} ->
          if is_map(item) and item["selected"] in [1, "1", true], do: value
        end)

      value ->
        to_string(value)
    end
  end

  defp checkbox(v) when v in ["on", "1", "true", 1, true], do: "1"
  defp checkbox(_), do: "0"

  defp run(socket, fun) do
    case fun.(socket.assigns.instance) do
      {:ok, _} ->
        {:noreply, socket |> assign(flash_msg: "Saved — apply to activate.") |> load_rules()}

      {:error, msg} ->
        {:noreply, assign(socket, error: msg)}
    end
  end

  defp visible_rules(rules, search) do
    q = String.downcase(search)

    if q == "" do
      rules
    else
      Enum.filter(rules, fn r ->
        [r.description, r.source, r.destination, r.protocol, r.action]
        |> Enum.any?(&String.contains?(String.downcase(to_string(&1)), q))
      end)
    end
  end

  @impl true
  def render(assigns) do
    assigns = assign(assigns, visible: visible_rules(assigns.rules, assigns.search))

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex flex-wrap items-center gap-3">
          <h1 class="text-lg font-medium text-base-content">Firewall rules — {@instance.name}</h1>
          <a
            href={~p"/instances/#{@instance.id}"}
            class="text-xs text-base-content/60 hover:text-base-content/80"
          >
            back to detail
          </a>
          <form phx-change="select_interface">
            <select
              name="interface"
              class="rounded border border-base-content/20 bg-base-100 p-1 text-sm text-base-content"
            >
              <option :for={i <- @interfaces} value={i.value} selected={i.value == @interface}>
                {i.label}
              </option>
            </select>
          </form>
          <button
            phx-click="new_rule"
            class="rounded bg-primary px-3 py-1 text-xs text-white hover:bg-primary/80"
          >
            New rule
          </button>
          <button
            phx-click="apply"
            data-confirm="Apply staged firewall changes on the box?"
            class="rounded bg-warning px-3 py-1 text-xs text-white hover:bg-warning/80"
          >
            Apply changes
          </button>
          <form phx-change="search" onsubmit="return false" class="ml-auto">
            <input
              type="text"
              name="q"
              value={@search}
              placeholder="Search rules…"
              phx-debounce="300"
              class="rounded-lg border border-base-content/20 bg-base-300 px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
            />
          </form>
        </div>

        <div
          :if={@flash_msg}
          class="mb-3 rounded border border-primary/40 bg-primary/10 p-2 text-sm text-primary"
        >
          {@flash_msg}
        </div>
        <div
          :if={@error}
          class="mb-3 rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>

        <%!-- Rule editor (create / edit / clone target). Field names are the
             exact OPNsense set_rule payload keys. --%>
        <form
          :if={@editor}
          phx-submit="save_rule"
          class="mb-4 rounded-lg border border-base-content/20 bg-base-200 p-4 text-sm"
        >
          <h2 class="mb-3 text-sm font-medium text-base-content/80">
            {if @editor_uuid, do: "Edit rule", else: "New rule"}
          </h2>
          <div class="grid gap-3 md:grid-cols-3">
            <label class="block text-xs text-base-content/60">
              Action
              <select
                name="rule[action]"
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 text-sm text-base-content"
              >
                <option :for={a <- ~w(pass block reject)} value={a} selected={@editor["action"] == a}>
                  {a}
                </option>
              </select>
            </label>
            <label class="block text-xs text-base-content/60">
              Interface
              <select
                name="rule[interface]"
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 text-sm text-base-content"
              >
                <option
                  :for={i <- @interfaces}
                  :if={i.value != ""}
                  value={i.value}
                  selected={@editor["interface"] == i.value}
                >
                  {i.label}
                </option>
              </select>
            </label>
            <label class="block text-xs text-base-content/60">
              Direction
              <select
                name="rule[direction]"
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 text-sm text-base-content"
              >
                <option :for={d <- ~w(in out)} value={d} selected={@editor["direction"] == d}>
                  {d}
                </option>
              </select>
            </label>
            <label class="block text-xs text-base-content/60">
              TCP/IP version
              <select
                name="rule[ipprotocol]"
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 text-sm text-base-content"
              >
                <option value="inet" selected={@editor["ipprotocol"] == "inet"}>IPv4</option>
                <option value="inet6" selected={@editor["ipprotocol"] == "inet6"}>IPv6</option>
              </select>
            </label>
            <label class="block text-xs text-base-content/60">
              Protocol
              <select
                name="rule[protocol]"
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 text-sm text-base-content"
              >
                <option
                  :for={p <- ~w(any TCP UDP TCP/UDP ICMP ESP GRE)}
                  value={p}
                  selected={@editor["protocol"] == p}
                >
                  {p}
                </option>
              </select>
            </label>
            <label class="block text-xs text-base-content/60">
              Description
              <input
                name="rule[description]"
                value={@editor["description"]}
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 text-sm text-base-content"
              />
            </label>
            <label class="block text-xs text-base-content/60">
              Source
              <input
                name="rule[source_net]"
                value={@editor["source_net"]}
                placeholder="any | net/CIDR | alias"
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 font-mono text-sm text-base-content"
              />
            </label>
            <label class="block text-xs text-base-content/60">
              Source port
              <input
                name="rule[source_port]"
                value={@editor["source_port"]}
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 font-mono text-sm text-base-content"
              />
            </label>
            <label class="block text-xs text-base-content/60">
              Destination
              <input
                name="rule[destination_net]"
                value={@editor["destination_net"]}
                placeholder="any | net/CIDR | alias"
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 font-mono text-sm text-base-content"
              />
            </label>
            <label class="block text-xs text-base-content/60">
              Destination port
              <input
                name="rule[destination_port]"
                value={@editor["destination_port"]}
                class="mt-0.5 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 font-mono text-sm text-base-content"
              />
            </label>
          </div>
          <div class="mt-3 flex items-center gap-4 text-xs text-base-content/70">
            <label class="flex items-center gap-1.5">
              <input
                type="checkbox"
                name="rule[enabled]"
                checked={@editor["enabled"] == "1"}
                class="accent-primary"
              /> Enabled
            </label>
            <label class="flex items-center gap-1.5">
              <input
                type="checkbox"
                name="rule[log]"
                checked={@editor["log"] == "1"}
                class="accent-primary"
              /> Log matching packets
            </label>
            <label class="flex items-center gap-1.5">
              <input
                type="checkbox"
                name="rule[quick]"
                checked={@editor["quick"] == "1"}
                class="accent-primary"
              /> Quick (first match)
            </label>
            <span class="ml-auto flex gap-2">
              <button
                type="button"
                phx-click="cancel_editor"
                class="rounded border border-base-content/20 px-3 py-1 text-base-content/80 hover:bg-base-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                class="rounded bg-primary px-3 py-1 text-white hover:bg-primary/80"
              >
                Save rule
              </button>
            </span>
          </div>
        </form>

        <table class="w-full text-left text-sm">
          <thead class="text-base-content/60">
            <tr class="border-b border-base-300">
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
            <%= for {r, idx} <- Enum.with_index(@visible) do %>
              <% prev = if idx > 0, do: Enum.at(@visible, idx - 1) %>
              <% next = Enum.at(@visible, idx + 1) %>
              <tr class="border-b border-base-300/50">
                <td class="py-1.5 pr-3">
                  <button
                    :if={r.editable}
                    phx-click="toggle"
                    phx-value-uuid={r.uuid}
                    phx-value-enabled={to_string(r.enabled)}
                    class={[
                      "rounded px-1.5 py-0.5 text-xs",
                      if(r.enabled,
                        do: "bg-primary/20 text-primary",
                        else: "bg-neutral text-base-content/70"
                      )
                    ]}
                  >
                    {if r.enabled, do: "on", else: "off"}
                  </button>
                  <span :if={not r.editable} class="text-xs text-base-content/40">
                    {if r.enabled, do: "on", else: "off"}
                  </span>
                </td>
                <td class="py-1.5 pr-3 text-base-content/80">{r.action}</td>
                <td class="py-1.5 pr-3 text-base-content/70">{r.protocol}</td>
                <td class="py-1.5 pr-3 font-mono text-xs text-base-content/70">
                  {r.source}{if r.source_port != "", do: ":#{r.source_port}"}
                </td>
                <td class="py-1.5 pr-3 font-mono text-xs text-base-content/70">
                  {r.destination}{if r.destination_port != "", do: ":#{r.destination_port}"}
                </td>
                <td class="py-1.5 pr-3 text-base-content/80">{r.description}</td>
                <td class="py-1.5 text-right text-xs">
                  <button
                    :if={r.editable and prev != nil and prev.editable}
                    phx-click="move_before"
                    phx-value-uuid={r.uuid}
                    phx-value-target={prev.uuid}
                    title="Move up"
                    class="rounded border border-base-content/20 px-1.5 py-0.5 text-base-content/70 hover:bg-base-300"
                  >
                    ↑
                  </button>
                  <button
                    :if={r.editable and next != nil and next.editable}
                    phx-click="move_before"
                    phx-value-uuid={next.uuid}
                    phx-value-target={r.uuid}
                    title="Move down"
                    class="rounded border border-base-content/20 px-1.5 py-0.5 text-base-content/70 hover:bg-base-300"
                  >
                    ↓
                  </button>
                  <button
                    :if={r.editable}
                    phx-click="edit_rule"
                    phx-value-uuid={r.uuid}
                    class="ml-1 rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300"
                  >
                    edit
                  </button>
                  <button
                    :if={r.editable}
                    phx-click="clone_rule"
                    phx-value-uuid={r.uuid}
                    title="Clone into a new rule"
                    class="ml-1 rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300"
                  >
                    clone
                  </button>
                  <button
                    :if={r.editable}
                    phx-click="delete"
                    phx-value-uuid={r.uuid}
                    data-confirm="Delete this rule? (apply to activate)"
                    class="ml-1 rounded border border-error/40 px-2 py-0.5 text-error hover:bg-error/15"
                  >
                    delete
                  </button>
                  <span :if={not r.editable} class="text-xs text-base-content/40">legacy</span>
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
        <div :if={@visible == [] and is_nil(@error)} class="py-4 text-sm text-base-content/60">
          {if @rules == [], do: "No rules on this interface.", else: "No matches."}
        </div>
      </section>
    </main>
    """
  end
end
