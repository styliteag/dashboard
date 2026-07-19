defmodule OrbitWeb.Components.SelectionTree do
  @moduledoc """
  Per-consumer selection editor — port of settings/SelectionTree.tsx. One
  component instance per settings tab (mattermost / telegram / email /
  checkmk): a global category checkbox grid on top, a per-instance preview
  tree below (expandable, every check row with its resolved on/off + the
  deciding level, box-level override toggles).

  Semantics mirror the react client exactly: a category checkbox is the
  presence of a GLOBAL include rule; a service checkbox at instance scope
  clears an explicit instance rule (back to inherit) or writes the opposite
  of the effective value (on→exclude mute, off→include add). Preview checks
  come from the hub cache via Export.evaluated (cheap — no live polls);
  on/by is resolved at render time against the freshly loaded rules, so a
  toggle only reloads rules, never re-evaluates the fleet.

  Channels additionally get the synthetic `availability` row (instance
  up/down — its own bucket, never exported to checkmk), a per-channel
  test-send button and the "subscribed but not configured" hint.

  Writes audit selection.rule.set/clear and scope-check per-instance rules
  through Scope.get_instance (invariant 1) like SelectionLive.
  """

  use OrbitWeb, :live_component

  alias Orbit.Auth.Scope
  alias Orbit.Checks.ServiceCheck
  alias Orbit.Selection

  # Display labels for every selectable category (SelectionTree.tsx
  # CATEGORY_LABELS mirror — keep in lock-step with Selection categories).
  @category_labels %{
    "availability" => "Instance up / down",
    "agent" => "Agent liveness",
    "maintenance" => "Maintenance mode",
    "ping" => "ICMP reachability",
    "http" => "HTTP reachability",
    "memory" => "Memory",
    "cpu" => "CPU",
    "load" => "Load average",
    "swap" => "Swap",
    "disk" => "Disks",
    "gateway" => "Gateways",
    "pf_states" => "pf state table",
    "ntp" => "NTP sync",
    "ipsec.service" => "IPsec service",
    "ipsec.tunnel" => "IPsec tunnels",
    "ipsec.tunnel_ping" => "IPsec ping monitors",
    "connectivity" => "Connectivity pings",
    "service" => "Vital services",
    "cert" => "Certificates",
    "iface_errors" => "Interface errors",
    "firmware" => "Firmware"
  }

  @by_note %{
    "instance" => "forced on (this box)",
    "instance_category" => "via box category",
    "global" => "via global",
    "global_category" => "via category",
    "default" => "off"
  }

  @impl true
  def mount(socket) do
    {:ok, assign(socket, open: MapSet.new(), test_busy: false, test_result: nil)}
  end

  @impl true
  def update(assigns, socket) do
    socket = assign(socket, consumer: assigns.consumer, current_user: assigns.current_user)

    socket =
      socket
      |> load_rules()
      |> then(fn s ->
        # Preview once per mount; the refresh button recomputes on demand.
        if s.assigns[:preview], do: s, else: assign(s, preview: build_preview(s))
      end)

    {:ok, socket}
  end

  defp load_rules(socket) do
    consumer = socket.assigns.consumer

    assign(socket,
      rules: Selection.consumer_rules(consumer),
      configured:
        if(consumer == "checkmk", do: nil, else: Orbit.Notifier.channel_configured?(consumer))
    )
  end

  # Hub-cache evaluation for every visible agent-mode instance (Export
  # seam: direct-poll instances don't preview). Channels prepend the
  # synthetic availability row (routes.py _availability_check parity).
  defp build_preview(socket) do
    channel? = socket.assigns.consumer != "checkmk"

    availability = %ServiceCheck{
      key: "availability",
      state: 0,
      summary: "Instance up / down alerts"
    }

    socket.assigns.current_user
    |> Orbit.Checks.Export.evaluated(DateTime.utc_now())
    |> Enum.map(fn {inst, checks} ->
      %{
        instance_id: inst.id,
        name: inst.name,
        device_type: inst.device_type,
        checks: if(channel?, do: [availability | checks], else: checks)
      }
    end)
    |> Enum.sort_by(&String.downcase(&1.name))
  end

  # -- events ----------------------------------------------------------------

  @impl true
  def handle_event("toggle_category", %{"cat" => cat}, socket) do
    consumer = socket.assigns.consumer

    if globally_included?(socket.assigns.rules, cat) do
      Selection.delete_rule(consumer, cat, nil)
      audit(socket, "selection.rule.clear", %{"name" => consumer, "kind" => cat})
    else
      Selection.set_rule(consumer, cat, "include", nil)

      audit(socket, "selection.rule.set", %{
        "name" => consumer,
        "mode" => "include",
        "kind" => cat
      })
    end

    {:noreply, load_rules(socket)}
  end

  def handle_event("toggle_service", %{"iid" => iid, "key" => key}, socket) do
    consumer = socket.assigns.consumer
    iid = String.to_integer(iid)

    cond do
      Scope.get_instance(iid, socket.assigns.current_user) == nil ->
        {:noreply, socket}

      explicit_rule?(socket.assigns.rules, iid, key) ->
        Selection.delete_rule(consumer, key, iid)
        audit(socket, "selection.rule.clear", %{"name" => consumer, "kind" => key})
        {:noreply, load_rules(socket)}

      true ->
        {on, _by} = Selection.resolve(consumer, key, iid, socket.assigns.rules)
        mode = if on, do: "exclude", else: "include"
        Selection.set_rule(consumer, key, mode, iid)
        audit(socket, "selection.rule.set", %{"name" => consumer, "mode" => mode, "kind" => key})
        {:noreply, load_rules(socket)}
    end
  end

  def handle_event("toggle_open", %{"iid" => iid}, socket) do
    iid = String.to_integer(iid)
    open = socket.assigns.open

    open =
      if MapSet.member?(open, iid), do: MapSet.delete(open, iid), else: MapSet.put(open, iid)

    {:noreply, assign(socket, open: open)}
  end

  def handle_event("refresh_preview", _params, socket) do
    {:noreply, assign(socket, preview: build_preview(socket))}
  end

  def handle_event("send_test", _params, socket) do
    if socket.assigns.test_busy do
      {:noreply, socket}
    else
      consumer = socket.assigns.consumer

      {:noreply,
       socket
       |> assign(test_busy: true, test_result: nil)
       |> start_async(:send_test, fn -> Orbit.Notifier.send_test(only: consumer) end)}
    end
  end

  @impl true
  def handle_async(:send_test, {:ok, results}, socket) do
    {:noreply, assign(socket, test_busy: false, test_result: List.first(results))}
  end

  def handle_async(:send_test, {:exit, _}, socket) do
    {:noreply,
     assign(socket,
       test_busy: false,
       test_result: %{channel: socket.assigns.consumer, status: "failed", detail: "test crashed"}
     )}
  end

  defp audit(socket, action, detail) do
    Orbit.Audit.write(
      action: action,
      result: "ok",
      user_id: socket.assigns.current_user.id,
      detail: detail
    )
  end

  # -- resolve helpers -------------------------------------------------------

  defp globally_included?(rules, cat) do
    Enum.any?(rules, fn {_c, i, s, m} -> is_nil(i) and s == cat and m == "include" end)
  end

  defp explicit_rule?(rules, iid, key) do
    Enum.any?(rules, fn {_c, i, s, _m} -> i == iid and s == key end)
  end

  defp category_label(key), do: Map.get(@category_labels, key, key)
  defp by_note(by), do: Map.get(@by_note, by, by)

  defp state_badge(0), do: {"OK", "bg-primary/20 text-primary"}
  defp state_badge(1), do: {"WARN", "bg-warning/20 text-warning"}
  defp state_badge(2), do: {"CRIT", "bg-error/20 text-error"}
  defp state_badge(_), do: {"UNKNOWN", "bg-base-300 text-base-content/70"}

  defp device_label("opnsense"), do: "OPNsense"
  defp device_label("pfsense"), do: "pfSense"
  defp device_label("securepoint"), do: "Securepoint"
  defp device_label("linux"), do: "Linux"
  defp device_label(other), do: other

  # -- render ----------------------------------------------------------------

  @impl true
  def render(assigns) do
    assigns = assign(assigns, channel?: assigns.consumer != "checkmk")

    ~H"""
    <div class="rounded-xl border border-base-300 bg-base-200/60 p-5">
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-base-content">
          {if @channel?, do: "Which alerts go to this channel", else: "Exported checks"}
        </h3>
        <button
          :if={@channel?}
          phx-click="send_test"
          phx-target={@myself}
          disabled={@test_busy}
          class="rounded-lg bg-neutral px-3 py-1.5 text-sm text-white hover:bg-neutral/80 disabled:opacity-50"
        >
          {if @test_busy, do: "Sending…", else: "Send test"}
        </button>
      </div>
      <p class="mt-1 text-xs text-base-content/60">
        Nothing is selected by default. Turn on a whole category globally, or add/mute a
        single service on one instance below. {if @channel?,
          do: "A box-level choice wins over the global one.",
          else: "Selection affects only the Checkmk export — the dashboard keeps showing all checks."}
      </p>

      <p
        :if={@channel? and @configured == false}
        class="mt-3 rounded-lg border border-warning/30 bg-warning/10 px-3 py-2 text-xs text-warning"
      >
        ⚠ This channel isn’t configured yet — selected alerts won’t be delivered until you
        fill in its settings above.
      </p>

      <p :if={@test_result} class="mt-3 text-xs">
        <span class="text-base-content/60">Test: </span>
        <span class={[
          @test_result.status == "sent" && "text-primary",
          @test_result.status == "failed" && "text-error",
          @test_result.status == "skipped" && "text-base-content/50"
        ]}>
          {@test_result.status}
        </span>
        <span :if={@test_result.detail != ""} class="ml-2 text-base-content/50">
          {@test_result.detail}
        </span>
      </p>

      <%!-- Global category toggles --%>
      <div class="mt-4 grid gap-2 sm:grid-cols-2">
        <label
          :for={cat <- Selection.categories_for(@consumer)}
          class="flex cursor-pointer items-center justify-between rounded-lg border border-base-300 bg-base-100/60 px-3 py-2"
        >
          <span class="text-sm text-base-content/80">{category_label(cat)}</span>
          <input
            type="checkbox"
            checked={globally_included?(@rules, cat)}
            phx-click="toggle_category"
            phx-value-cat={cat}
            phx-target={@myself}
            class="h-4 w-4 cursor-pointer accent-primary"
          />
        </label>
      </div>

      <%!-- Per-instance live preview tree --%>
      <div class="mt-5 flex items-center justify-between">
        <h4 class="text-xs font-semibold uppercase tracking-wide text-base-content/50">
          {if @channel?, do: "Per instance", else: "Current export per instance"}
        </h4>
        <button
          phx-click="refresh_preview"
          phx-target={@myself}
          class="rounded px-2 py-1 text-xs text-base-content/60 hover:bg-base-300"
        >
          ⟳ Refresh
        </button>
      </div>

      <div class="mt-2 space-y-2">
        <div
          :for={inst <- @preview}
          class="overflow-hidden rounded-lg border border-base-300"
        >
          <button
            phx-click="toggle_open"
            phx-value-iid={inst.instance_id}
            phx-target={@myself}
            class="flex w-full items-center justify-between bg-base-100/70 px-3 py-2 text-left hover:bg-base-100"
          >
            <span class="flex items-center gap-2 text-sm text-base-content">
              <span class="text-base-content/50">
                {if MapSet.member?(@open, inst.instance_id), do: "▾", else: "▸"}
              </span>
              {inst.name}
              <span class="text-xs text-base-content/50">{device_label(inst.device_type)}</span>
            </span>
            <span class="text-xs text-base-content/50">
              {Enum.count(inst.checks, fn c ->
                elem(Selection.resolve(@consumer, c.key, inst.instance_id, @rules), 0)
              end)}/{length(inst.checks)} selected
            </span>
          </button>

          <ul
            :if={MapSet.member?(@open, inst.instance_id)}
            class="divide-y divide-base-300/60"
          >
            <li
              :for={c <- inst.checks}
              class={[
                "flex items-center gap-3 px-3 py-1.5 text-xs",
                not elem(Selection.resolve(@consumer, c.key, inst.instance_id, @rules), 0) &&
                  "opacity-50"
              ]}
            >
              <input
                type="checkbox"
                checked={elem(Selection.resolve(@consumer, c.key, inst.instance_id, @rules), 0)}
                phx-click="toggle_service"
                phx-value-iid={inst.instance_id}
                phx-value-key={c.key}
                phx-target={@myself}
                title="Toggle this service for this instance"
                class="h-3.5 w-3.5 cursor-pointer accent-primary"
              />
              <span class={[
                "rounded px-1.5 py-0.5",
                elem(state_badge(c.state), 1)
              ]}>
                {elem(state_badge(c.state), 0)}
              </span>
              <span class="font-mono text-base-content/80">{c.key}</span>
              <span class="truncate text-base-content/50">{c.summary}</span>
              <span class="ml-auto flex items-center gap-2 whitespace-nowrap">
                <span class="text-base-content/40">
                  {by_note(elem(Selection.resolve(@consumer, c.key, inst.instance_id, @rules), 1))}
                </span>
                <button
                  :if={explicit_rule?(@rules, inst.instance_id, c.key)}
                  phx-click="toggle_service"
                  phx-value-iid={inst.instance_id}
                  phx-value-key={c.key}
                  phx-target={@myself}
                  title="Clear this box-level override and inherit"
                  class="text-base-content/50 hover:text-base-content"
                >
                  ↺
                </button>
              </span>
            </li>
          </ul>
        </div>
        <p :if={@preview == []} class="text-xs text-base-content/50">No instances.</p>
      </div>
    </div>
    """
  end
end
