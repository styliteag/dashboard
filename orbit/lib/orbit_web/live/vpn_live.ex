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

  import OrbitWeb.Components.PingMonitorDialog, only: [ping_monitor_dialog: 1]

  import OrbitWeb.Components.ListKit
  import OrbitWeb.Components.CommentEditor, only: [comment_editor: 1]

  alias OrbitWeb.Components.CommentEditor

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
       active_tag: nil,
       sort_col: "state",
       sort_dir: :asc,
       busy: MapSet.new(),
       msg: nil,
       expanded: MapSet.new(),
       ping_editor: nil,
       ping_test: nil,
       ping_test_busy: false,
       history: nil,
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

  def handle_event("tag_filter", %{"tag" => ""}, socket),
    do: {:noreply, assign(socket, active_tag: nil)}

  def handle_event("tag_filter", %{"tag" => tag}, socket) do
    tag = if socket.assigns.active_tag == tag, do: nil, else: tag
    {:noreply, assign(socket, active_tag: tag)}
  end

  def handle_event("sort", %{"col" => col}, socket) when col in @sort_cols do
    dir =
      if socket.assigns.sort_col == col and socket.assigns.sort_dir == :asc,
        do: :desc,
        else: :asc

    {:noreply, assign(socket, sort_col: col, sort_dir: dir)}
  end

  def handle_event("row_gui_open", %{"id" => id} = p, socket) do
    {:noreply, gui_open_row(socket, id, p["path"])}
  end

  def handle_event("toggle_expand", %{"key" => key}, socket) do
    expanded = socket.assigns.expanded

    expanded =
      if MapSet.member?(expanded, key),
        do: MapSet.delete(expanded, key),
        else: MapSet.put(expanded, key)

    {:noreply, assign(socket, expanded: expanded)}
  end

  # Phase-2 ping-monitor dialog (PingMonitorDialog parity) — the instance id
  # comes from the DOM, so every step re-resolves it through the caller's
  # scope (invariant 1). "Test" runs the agent's one-off ipsec.ping_test on
  # the CURRENT form values, before anything is saved.
  def handle_event("p2mon_open", params, socket) do
    with true <- socket.assigns.writable,
         {iid, ""} <- Integer.parse(to_string(params["iid"] || "")),
         inst when not is_nil(inst) <- Scope.get_instance(iid, socket.assigns.current_user) do
      mon = p2_monitor(socket.assigns.monitors, inst.id, params["child"])

      editor = %{
        instance_id: inst.id,
        instance_name: inst.name,
        tunnel_id: params["tunnel"] || "",
        child_name: params["child"] || "",
        local_ts: params["lts"] || "",
        remote_ts: params["rts"] || "",
        monitor_id: mon && mon.id,
        source: (mon && mon.source) || params["suggested"] || "",
        destination: (mon && mon.destination) || "",
        ping_count: (mon && mon.ping_count) || 3,
        enabled: is_nil(mon) or mon.enabled
      }

      {:noreply, assign(socket, ping_editor: editor, ping_test: nil)}
    else
      _ -> {:noreply, socket}
    end
  end

  # Tunnel history dialog (TunnelHistoryDialog/TunnelGraphDialog parity):
  # recorded transitions + an up/down timeline. Read-only, still re-scoped.
  def handle_event("history_open", %{"iid" => iid, "tunnel" => tunnel_id} = params, socket) do
    with {nid, ""} <- Integer.parse(iid),
         inst when not is_nil(inst) <- Scope.get_instance(nid, socket.assigns.current_user) do
      events = Orbit.Ipsec.History.read(inst.id, tunnel_id, 100)

      live =
        Enum.find(socket.assigns.tunnels, &(&1.instance_id == inst.id and &1.id == tunnel_id))

      {:noreply,
       assign(socket,
         history: %{
           mode: if(params["mode"] == "graph", do: :graph, else: :history),
           instance_name: inst.name,
           tunnel_id: tunnel_id,
           label: params["label"] || tunnel_id,
           up: params["up"] == "true",
           phase2_up: (live && live.phase2_up) || 0,
           phase2_total: (live && live.phase2_total) || 0,
           events: events
         }
       )}
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("history_close", _params, socket) do
    {:noreply, assign(socket, history: nil)}
  end

  def handle_event("p2mon_cancel", _params, socket) do
    {:noreply, assign(socket, ping_editor: nil, ping_test: nil)}
  end

  # phx-change keeps the editor assign in sync so Test always probes the
  # CURRENT form values without submitting.
  def handle_event("p2mon_change", %{"mon" => attrs}, socket) do
    case socket.assigns.ping_editor do
      nil ->
        {:noreply, socket}

      editor ->
        {:noreply,
         assign(socket,
           ping_editor: %{
             editor
             | source: attrs["source"] || "",
               destination: attrs["destination"] || "",
               ping_count: attrs["ping_count"] || editor.ping_count,
               enabled: attrs["enabled"] in ["true", "on"]
           }
         )}
    end
  end

  def handle_event("p2mon_test", _params, socket) do
    editor = socket.assigns.ping_editor

    with true <- socket.assigns.writable,
         false <- socket.assigns.ping_test_busy,
         %{} <- editor,
         inst when not is_nil(inst) <-
           Scope.get_instance(editor.instance_id, socket.assigns.current_user) do
      payload = %{
        "source" => String.trim(to_string(editor.source)),
        "destination" => String.trim(to_string(editor.destination)),
        "ping_count" => to_string(editor.ping_count)
      }

      {:noreply,
       socket
       |> assign(ping_test_busy: true, ping_test: nil)
       |> start_async(:ping_test, fn ->
         result = Hub.send_command(inst.id, "ipsec.ping_test", payload, 20_000)
         if is_map(result), do: result, else: %{"success" => false, "output" => "no agent"}
       end)}
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("p2mon_save", %{"mon" => attrs}, socket) do
    editor = socket.assigns.ping_editor

    with %{} <- editor,
         true <- socket.assigns.writable,
         inst when not is_nil(inst) <-
           Scope.get_instance(editor.instance_id, socket.assigns.current_user) do
      attrs =
        Map.merge(attrs, %{
          "tunnel_id" => editor.tunnel_id,
          "child_name" => editor.child_name,
          "local_ts" => editor.local_ts,
          "remote_ts" => editor.remote_ts
        })

      result =
        case editor.monitor_id do
          nil -> Orbit.Monitors.create_ipsec(inst.id, attrs)
          mid -> Orbit.Monitors.update_ipsec(inst.id, mid, attrs)
        end

      case result do
        :ok ->
          Audit.write(
            action:
              if(editor.monitor_id,
                do: "ipsec.ping_monitor.update",
                else: "ipsec.ping_monitor.create"
              ),
            result: "ok",
            user_id: socket.assigns.current_user.id,
            target_type: "instance",
            target_id: inst.id
          )

          {:noreply, socket |> assign(ping_editor: nil, ping_test: nil, msg: nil) |> load()}

        {:error, msg} ->
          {:noreply, assign(socket, msg: {:error, msg})}
      end
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("p2mon_delete", %{"id" => raw, "iid" => raw_iid}, socket) do
    with true <- socket.assigns.writable,
         {id, ""} <- Integer.parse(raw),
         {iid, ""} <- Integer.parse(raw_iid),
         inst when not is_nil(inst) <- Scope.get_instance(iid, socket.assigns.current_user) do
      :ok = Orbit.Monitors.delete_ipsec(inst.id, id)

      Audit.write(
        action: "ipsec.ping_monitor.delete",
        result: "ok",
        user_id: socket.assigns.current_user.id,
        target_type: "instance",
        target_id: inst.id
      )

      {:noreply, socket |> assign(msg: nil, ping_editor: nil, ping_test: nil) |> load()}
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("comment_save", params, socket),
    do: {:noreply, socket |> CommentEditor.save(params) |> load()}

  def handle_event("comment_clear", params, socket),
    do: {:noreply, socket |> CommentEditor.clear(params) |> load()}

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
  def handle_async(:ping_test, {:ok, result}, socket) do
    outcome =
      if result["success"] do
        rtt = result["ping_rtt_ms"]
        loss = result["ping_loss_pct"]

        {:ok,
         "#{result["ping_state"] || "ok"}" <>
           if(is_number(rtt), do: " — #{rtt} ms", else: "") <>
           if(is_number(loss), do: ", #{loss}% loss", else: "")}
      else
        {:error, String.slice(to_string(result["output"] || "test failed"), 0, 200)}
      end

    {:noreply, assign(socket, ping_test_busy: false, ping_test: outcome)}
  end

  def handle_async(:ping_test, {:exit, _}, socket) do
    {:noreply, assign(socket, ping_test_busy: false, ping_test: {:error, "test crashed"})}
  end

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
    # NOT filtered to agent_mode?: a direct-polled box has an `ipsec` section
    # in the hub cache too (Securepoint fills it via the swanctl-over-SSH
    # enrichment). The filter hid every polled box's tunnels from the fleet
    # view while its own detail page listed them. The rows below are pure
    # display data — this page has no agent-only tunnel actions.
    vpn_instances =
      socket.assigns.current_user
      |> Instances.list_visible()

    monitors = Orbit.Monitors.list_ipsec_for(Enum.map(vpn_instances, & &1.id))

    tunnels =
      Enum.flat_map(vpn_instances, fn inst ->
        ipsec = Hub.cache_entry(inst.id)["ipsec"] || %{}
        gui_openable = Orbit.GUI.openable(inst) == :ok

        for t <- ipsec["tunnels"] || [] do
          status = (t["status"] || "") |> to_string() |> String.downcase()

          %{
            instance_id: inst.id,
            instance_name: inst.name,
            device_type: inst.device_type,
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
            bytes_out: int0(t["bytes_out"]),
            children: t["children"] || [],
            tags: inst.tags || []
          }
        end
      end)

    assign(socket,
      tunnels: tunnels,
      monitors: monitors,
      comments: CommentEditor.lookup(vpn_instances)
    )
  end

  defp p2_monitor(monitors, instance_id, child_name) do
    monitors
    |> Map.get(instance_id, [])
    |> Enum.find(&(&1.child_name == to_string(child_name || "")))
  end

  defp visible(a) do
    q = String.downcase(a.search)

    a.tunnels
    |> Enum.filter(fn t ->
      q == "" or
        String.contains?(String.downcase(t.instance_name), q) or
        String.contains?(String.downcase(to_string(t.label)), q) or
        String.contains?(String.downcase(t.remote), q) or
        Enum.any?(t.tags, &String.contains?(String.downcase(&1), q))
    end)
    |> Enum.filter(fn t ->
      case a.state_filter do
        "all" -> true
        "up" -> t.up
        "down" -> not t.up
      end
    end)
    |> Enum.filter(&(a.active_tag == nil or a.active_tag in &1.tags))
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
        down_count: Enum.count(assigns.tunnels, &(not &1.up)),
        all_tags: assigns.tunnels |> Enum.flat_map(& &1.tags) |> Enum.uniq() |> Enum.sort()
      )

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:vpn} current_user={@current_user} />

      <section class="p-6">
        <h1 class="flex items-center gap-2 mb-4 text-lg font-medium text-base-content">
          <Icons.icon name={:vpn} class="h-5 w-5 text-base-content/60" /> IPsec tunnels
          <span class="ml-2 text-sm text-base-content/60">({length(@tunnels)})</span>
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
            color="text-primary"
            event="state_filter"
            value_name="up"
            active={@state_filter == "up"}
          />
          <.kpi_tile
            label="Down"
            value={@down_count}
            color="text-error"
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
            placeholder="Search instance, tunnel, remote, tag…"
            phx-debounce="300"
            class="w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </form>

        <div :if={@all_tags != []} class="mb-3 flex flex-wrap gap-2">
          <button phx-click="tag_filter" phx-value-tag="" class={chip(@active_tag == nil)}>
            All
          </button>
          <button
            :for={tag <- @all_tags}
            phx-click="tag_filter"
            phx-value-tag={tag}
            class={chip(@active_tag == tag)}
          >
            {tag}
          </button>
        </div>

        <div
          :if={@msg}
          class={[
            "mb-3 rounded px-3 py-2 text-xs",
            case @msg do
              {:ok, _} -> "bg-primary/15 text-primary"
              _ -> "bg-error/15 text-error"
            end
          ]}
        >
          {elem(@msg, 1)}
        </div>

        <div :if={@tunnels == []} class="text-sm text-base-content/60">
          No IPsec tunnels reported in your scope.
        </div>
        <div :if={@tunnels != [] and @rows == []} class="text-sm text-base-content/60">
          No matches.
        </div>

        <div :if={@rows != []} class="overflow-x-auto rounded-lg border border-base-300">
          <table class="w-full text-left text-sm">
            <thead class="bg-base-200 text-xs text-base-content/60">
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
              <%= for t <- @rows do %>
                <% key = "#{t.instance_id}:#{t.id}" %>
                <tr class="border-b border-base-300/50 last:border-0">
                  <td class="whitespace-nowrap px-3 py-2">
                    <button
                      :if={t.children != []}
                      phx-click="toggle_expand"
                      phx-value-key={key}
                      title="Show phase-2 child SAs"
                      class="mr-2 inline-flex h-6 w-6 items-center justify-center rounded border border-base-content/20 text-base text-base-content/80 hover:bg-base-300"
                    >
                      {if MapSet.member?(@expanded, key), do: "▾", else: "▸"}
                    </button>
                    <span class={[
                      "inline-block h-2.5 w-2.5 rounded-full",
                      if(t.up, do: "bg-primary", else: "bg-error")
                    ]}></span>
                  </td>
                  <td class="px-3 py-2">
                    <a
                      href={~p"/instances/#{t.instance_id}"}
                      class="text-base-content hover:text-primary"
                    >
                      {t.instance_name}
                    </a>
                    <.webui_link
                      instance_id={t.instance_id}
                      openable={t.gui_openable}
                      path={ipsec_ui_path(t.device_type)}
                      title="Open the firewall's IPsec status page (tunneled)"
                    />
                    <.shell_link instance_id={t.instance_id} shell_enabled={t.shell_enabled} />
                  </td>
                  <td class="px-3 py-2 text-base-content/80">
                    {t.label}
                    <.comment_editor
                      text={CommentEditor.text(@comments, t.instance_id, "ipsec", t.id)}
                      writable={@writable}
                      instance_id={t.instance_id}
                      kind="ipsec"
                      entity_key={t.id}
                    />
                  </td>
                  <td class="px-3 py-2 text-base-content/60">{t.remote}</td>
                  <td class="px-3 py-2 text-base-content/70">
                    <span :if={t.phase2_total > 0}>{t.phase2_up}/{t.phase2_total} up</span>
                    <span :if={t.phase2_total == 0}>—</span>
                  </td>
                  <td class="px-3 py-2 text-base-content/70">{duration(t.uptime_s)}</td>
                  <td class="px-3 py-2 text-base-content/70">
                    {bytes(t.bytes_in)} / {bytes(t.bytes_out)}
                  </td>
                  <td :if={@writable} class="px-3 py-2 text-right text-xs">
                    <button
                      phx-click="history_open"
                      phx-value-iid={t.instance_id}
                      phx-value-tunnel={t.id}
                      phx-value-label={t.label}
                      phx-value-up={to_string(t.up)}
                      phx-value-mode="graph"
                      class="mr-1 rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300"
                    >
                      Graph
                    </button>
                    <button
                      phx-click="history_open"
                      phx-value-iid={t.instance_id}
                      phx-value-tunnel={t.id}
                      phx-value-label={t.label}
                      phx-value-up={to_string(t.up)}
                      phx-value-mode="history"
                      class="mr-1 rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300"
                    >
                      History
                    </button>
                    <button
                      phx-click="reconnect"
                      phx-value-iid={t.instance_id}
                      phx-value-id={t.id}
                      phx-value-uid={t.unique_id}
                      disabled={MapSet.member?(@busy, "#{t.instance_id}:#{t.id}")}
                      class="rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {if MapSet.member?(@busy, "#{t.instance_id}:#{t.id}"),
                        do: "…",
                        else: "Reconnect"}
                    </button>
                  </td>
                </tr>
                <tr
                  :for={ch <- t.children}
                  :if={MapSet.member?(@expanded, key)}
                  class="border-b border-base-300/30 bg-base-100/40 text-xs last:border-0"
                >
                  <td class="px-3 py-1"></td>
                  <td class="px-3 py-1 text-base-content/40">{t.instance_name}</td>
                  <td class="px-3 py-1 pl-8 text-base-content/60">{ch["name"] || "child"}</td>
                  <td class="px-3 py-1 text-base-content/60" colspan="2">
                    {ch["local_ts"] || "?"} ⇄ {ch["remote_ts"] || "?"}
                  </td>
                  <td class={[
                    "px-3 py-1",
                    if(child_up?(ch), do: "text-primary", else: "text-error")
                  ]}>
                    {ch["status"] || "?"}
                  </td>
                  <td class="px-3 py-1 text-base-content/60" colspan={if @writable, do: 2, else: 1}>
                    <% mon = p2_monitor(@monitors, t.instance_id, ch["name"]) %>
                    <span :if={ch["ping_state"] not in [nil, "none"]} class="mr-2">
                      ping {ch["ping_state"]}
                    </span>
                    <span
                      :if={ch["phase2_dup_persistent"] == true}
                      title="Duplicate CHILD_SAs for this selector persisted over several pushes — usually a rekey leak"
                      class="mr-2 text-warning"
                    >
                      ⚠ {ch["dup_count"] || 2}× SAs
                    </span>
                    <span :if={mon} class="mr-2 text-base-content/40">
                      monitor {if mon.source != "", do: "#{mon.source} "}→ {mon.destination}
                      <span :if={not mon.enabled}>(disabled)</span>
                    </span>
                    <button
                      :if={@writable}
                      phx-click="p2mon_open"
                      phx-value-iid={t.instance_id}
                      phx-value-tunnel={t.id}
                      phx-value-child={ch["name"] || ""}
                      phx-value-lts={ch["local_ts"] || ""}
                      phx-value-rts={ch["remote_ts"] || ""}
                      phx-value-suggested={ch["suggested_source"] || ""}
                      class="rounded border border-base-content/20 px-2 py-0.5 text-base-content/80 hover:bg-base-300"
                    >
                      {if mon, do: "Edit ping", else: "Add ping"}
                    </button>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>

        <%!-- Tunnel history dialog: up/down timeline + recorded transitions. --%>
        <div
          :if={@history}
          class="fixed inset-0 z-50 flex items-center justify-center bg-base-100/80 p-4"
        >
          <div class="max-h-[80vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-base-content/20 bg-base-200 p-5">
            <div class="flex items-center justify-between">
              <h3 class="text-sm font-medium text-base-content">
                {if @history.mode == :graph, do: "Tunnel graph", else: "Tunnel history"} — {@history.label}
                <span class="ml-1 text-xs text-base-content/60">{@history.instance_name}</span>
              </h3>
              <button
                phx-click="history_close"
                class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
              >
                Close
              </button>
            </div>

            <%!-- Three state lanes from the transition log (TunnelGraphDialog
                 parity): green up, red down, amber partial, grey no data. --%>
            <% lanes =
              Orbit.Ipsec.History.lanes(
                @history.events,
                %{
                  up: @history.up,
                  phase2_up: @history.phase2_up,
                  phase2_total: @history.phase2_total
                },
                DateTime.utc_now()
              ) %>
            <div class="mt-4 space-y-2">
              <div
                :for={
                  {label, segs} <- [
                    {"Phase 1", lanes.phase1},
                    {"Phase 2", lanes.phase2},
                    {"Ping", lanes.ping}
                  ]
                }
                class="flex items-center gap-2"
              >
                <span class="w-16 text-right text-[10px] text-base-content/60">{label}</span>
                <div class={[
                  "relative flex-1 overflow-hidden rounded bg-base-300",
                  if(@history.mode == :graph, do: "h-7", else: "h-3.5")
                ]}>
                  <div
                    :for={seg <- segs}
                    class={["absolute h-full", lane_color(seg.state)]}
                    style={"left: #{Float.round(seg.left, 2)}%; width: #{Float.round(seg.width, 2)}%"}
                  >
                  </div>
                </div>
              </div>
              <div class="flex justify-between pl-[4.5rem] text-[10px] text-base-content/40">
                <span :if={@history.events != []}>{fmt_event_ts(lanes.window_start)}</span>
                <span :if={@history.events == []}>no recorded transitions yet</span>
                <span>now</span>
              </div>
              <div class="flex gap-3 pl-[4.5rem] text-[10px] text-base-content/60">
                <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-primary"></span>up</span>
                <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-warning"></span>partial</span>
                <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-error"></span>down</span>
                <span><span class="mr-1 inline-block h-2 w-2 rounded-sm bg-neutral"></span>no data</span>
              </div>
            </div>

            <table
              :if={@history.mode == :history and @history.events != []}
              class="mt-4 w-full text-left text-xs"
            >
              <thead class="text-base-content/60">
                <tr class="border-b border-base-300">
                  <th class="py-1 pr-3 font-medium">Time (UTC)</th>
                  <th class="py-1 pr-3 font-medium">Event</th>
                  <th class="py-1 pr-3 font-medium">Phase 2</th>
                  <th class="py-1 font-medium">Change</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={e <- @history.events} class="border-b border-base-300/50 last:border-0">
                  <td class="py-1 pr-3 font-mono text-base-content/60">{fmt_event_ts(e.ts)}</td>
                  <td class={["py-1 pr-3", event_color(e.event_type)]}>{e.event_type}</td>
                  <td class="py-1 pr-3 text-base-content/60">{e.child_name}</td>
                  <td class="py-1 text-base-content/70">{e.old_value} → {e.new_value}</td>
                </tr>
              </tbody>
            </table>
            <p
              :if={@history.mode == :history and @history.events == []}
              class="mt-4 text-sm text-base-content/60"
            >
              No transitions recorded yet — events appear as soon as the tunnel
              changes state (orbit records them per agent push).
            </p>
          </div>
        </div>

        <.ping_monitor_dialog
          editor={@ping_editor}
          busy={@ping_test_busy}
          result={@ping_test}
        />
      </section>
    </main>
    """
  end

  defp lane_color(:up), do: "bg-primary"
  defp lane_color(:partial), do: "bg-warning"
  defp lane_color(:down), do: "bg-error"
  defp lane_color(:unknown), do: "bg-neutral"

  defp event_color("phase1_up"), do: "text-primary"
  defp event_color("ping_ok"), do: "text-primary"
  defp event_color("phase1_down"), do: "text-error"
  defp event_color("ping_fail"), do: "text-error"
  defp event_color(_), do: "text-warning"

  defp fmt_event_ts(ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S UTC")

  defp child_up?(ch) do
    String.downcase(to_string(ch["status"] || "")) in @ipsec_up
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
