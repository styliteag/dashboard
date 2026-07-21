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
  import OrbitWeb.Components.TunnelHistoryDialog, only: [tunnel_history_dialog: 1]
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
       # Problems first (python parity): a fleet VPN page is opened because
       # something is down, and on a large fleet the down tunnels sit far
       # below the fold of an unfiltered list.
       state_filter: "down",
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
       fleet_graph: false,
       fleet_window: "7d",
       fleet_events: %{},
       fleet_cap: 40,
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
      live =
        Enum.find(socket.assigns.tunnels, &(&1.instance_id == inst.id and &1.id == tunnel_id))

      {:noreply,
       assign(socket,
         history:
           history_assign(
             %{
               mode: if(params["mode"] == "graph", do: :graph, else: :history),
               instance_id: inst.id,
               instance_name: inst.name,
               tunnel_id: tunnel_id,
               label: params["label"] || tunnel_id,
               up: params["up"] == "true",
               phase2_up: (live && live.phase2_up) || 0,
               phase2_total: (live && live.phase2_total) || 0
             },
             "7d"
           )
       )}
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("history_close", _params, socket) do
    {:noreply, assign(socket, history: nil)}
  end

  # Re-reads rather than filtering what is loaded: a wider window needs rows
  # the first query never fetched.
  def handle_event("history_window", %{"window" => window}, socket) do
    case socket.assigns.history do
      nil -> {:noreply, socket}
      h -> {:noreply, assign(socket, history: history_assign(h, window))}
    end
  end

  # Loaded on demand, not on mount: it is one query over every visible box and
  # most visits to this page never open the graph.
  def handle_event("fleet_graph", _params, socket) do
    if socket.assigns.fleet_graph do
      {:noreply, assign(socket, fleet_graph: false, fleet_events: %{})}
    else
      {:noreply, socket |> assign(fleet_graph: true) |> load_fleet_events()}
    end
  end

  def handle_event("fleet_window", %{"window" => window}, socket) when window in ~w(24h 7d 30d) do
    {:noreply, socket |> assign(fleet_window: window) |> load_fleet_events()}
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

  # Ask the box for fresh tunnel status instead of waiting for the next push.
  # The instance page has had this since the section was written; from the
  # fleet page — where an operator watches a tunnel they just reconnected —
  # the only option was to sit through the refresh interval.
  def handle_event("recheck", %{"iid" => iid}, socket) do
    key = "recheck:#{iid}"

    with true <- not MapSet.member?(socket.assigns.busy, key),
         {nid, ""} <- Integer.parse(iid),
         inst when not is_nil(inst) <- Scope.get_instance(nid, socket.assigns.current_user) do
      {:noreply,
       socket
       |> assign(busy: MapSet.put(socket.assigns.busy, key))
       |> start_async({:recheck, key}, fn ->
         Hub.send_command(inst.id, "status.refresh", %{}, 20_000)
         :ok
       end)}
    else
      _ -> {:noreply, socket}
    end
  end

  @impl true
  def handle_async({:recheck, key}, _result, socket) do
    # Whatever the box answered, re-read the cache: a refresh that timed out
    # may still have landed, and a stale table is the thing being fixed.
    {:noreply,
     socket
     |> assign(busy: MapSet.delete(socket.assigns.busy, key))
     |> load()}
  end

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

  # Default 7d rather than everything: the fleet has tunnels with a year of
  # transitions, and "all" squeezes last night's outage into one pixel.
  # Cap the drawn rows, and say so in the UI when it bites.
  @fleet_cap 40

  defp load_fleet_events(socket) do
    # `rows` is derived in render/1, not an assign — read the source list, and
    # fetch for every visible instance so changing the filter needs no reload.
    ids = socket.assigns.tunnels |> Enum.map(& &1.instance_id) |> Enum.uniq()
    since = Orbit.Ipsec.History.window_start(socket.assigns.fleet_window, DateTime.utc_now())

    assign(socket,
      fleet_events: Orbit.Ipsec.History.read_many(ids, since),
      fleet_cap: @fleet_cap
    )
  end

  # One phase-1 lane per row over the shared window, so the lanes line up
  # vertically and a fleet-wide event reads as a vertical stripe.
  defp fleet_lanes(rows, events, window) do
    now = DateTime.utc_now()
    start = Orbit.Ipsec.History.window_start(window, now)

    rows
    |> Enum.take(@fleet_cap)
    |> Enum.map(fn row ->
      lanes =
        Orbit.Ipsec.History.lanes(
          Map.get(events, {row.instance_id, row.id}, []),
          %{up: row.up, phase2_up: row.phase2_up, phase2_total: row.phase2_total},
          now,
          start
        )

      %{label: "#{row.instance_name} · #{row.label}", segments: lanes.phase1}
    end)
  end

  defp history_assign(history, window) do
    now = DateTime.utc_now()
    start = Orbit.Ipsec.History.window_start(window, now)

    history
    |> Map.put(:window, window)
    |> Map.put(:window_start, start)
    |> Map.put(
      :events,
      Orbit.Ipsec.History.read(history.instance_id, history.tunnel_id, 200, start)
    )
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
        entry = Hub.cache_entry(inst.id)
        ipsec = entry["ipsec"] || %{}
        gui_openable = Orbit.GUI.openable(inst) == :ok
        # The box's real public address, for the lip-mismatch hint below.
        public_ip = Orbit.ExternalIp.build(entry)

        for t <- ipsec["tunnels"] || [] do
          status = (t["status"] || "") |> to_string() |> String.downcase()

          %{
            instance_id: inst.id,
            instance_name: inst.name,
            device_type: inst.device_type,
            shell_enabled: inst.shell_enabled,
            gui_openable: gui_openable,
            base_url: inst.base_url,
            id: to_string(t["id"] || t["description"] || "tunnel"),
            unique_id: to_string(t["unique_id"] || ""),
            label: t["description"] || t["id"] || "tunnel",
            status: t["status"] || "?",
            up: status in @ipsec_up,
            remote: t["remote"] || "",
            local: to_string(t["local"] || ""),
            lip_mismatch: Orbit.Ipsec.LocalEndpoint.mismatch?(t["local"], t["status"], public_ip),
            box_public_ip: public_ip[:ipv4],
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

        <%!-- Fleet graph: one lane per tunnel over a shared window. The
             per-tunnel dialog answers "what did THIS tunnel do"; the question
             this answers is "did they all drop at 03:12, or is it just the
             one?" — which no single-tunnel view can. --%>
        <div :if={@rows != []} class="mb-3 flex items-center gap-2">
          <button
            phx-click="fleet_graph"
            class={[
              "rounded border border-base-content/20 px-2 py-0.5 text-xs",
              if(@fleet_graph,
                do: "bg-base-300 text-base-content",
                else: "text-base-content/70 hover:bg-base-300"
              )
            ]}
          >
            Fleet graph
          </button>
          <div :if={@fleet_graph} class="flex items-center gap-1">
            <button
              :for={key <- ~w(24h 7d 30d)}
              phx-click="fleet_window"
              phx-value-window={key}
              class={[
                "rounded px-2 py-0.5 text-[10px]",
                if(@fleet_window == key,
                  do: "bg-base-300 text-base-content",
                  else: "text-base-content/60 hover:bg-base-300/60"
                )
              ]}
            >
              {key}
            </button>
          </div>
        </div>

        <div
          :if={@fleet_graph and @rows != []}
          class="mb-4 rounded-lg border border-base-300 bg-base-200 p-4"
        >
          <div :for={row <- fleet_lanes(@rows, @fleet_events, @fleet_window)} class="mb-1.5">
            <div class="flex items-center gap-2">
              <span class="w-40 shrink-0 truncate text-right text-[10px] text-base-content/60">
                {row.label}
              </span>
              <div class="relative h-3 flex-1 overflow-hidden rounded bg-base-300">
                <div
                  :for={seg <- row.segments}
                  class={[
                    "absolute h-full",
                    OrbitWeb.Components.TunnelHistoryDialog.lane_color(seg.state)
                  ]}
                  style={"left: #{Float.round(seg.left, 2)}%; width: #{Float.round(seg.width, 2)}%"}
                >
                </div>
              </div>
            </div>
          </div>
          <div class="mt-2 flex justify-between pl-[10.5rem] text-[10px] text-base-content/40">
            <span>{@fleet_window} ago</span>
            <span>now</span>
          </div>
          <%!-- Never silently truncate: an operator reading "all quiet" off a
               graph that dropped rows would be reading a lie. --%>
          <p :if={length(@rows) > @fleet_cap} class="mt-2 text-[10px] text-warning">
            Showing the first {@fleet_cap} of {length(@rows)} tunnels — narrow the filter
            to see the rest.
          </p>
        </div>

        <div :if={@rows != []} class="overflow-x-auto rounded-lg border border-base-300">
          <table class="w-full min-w-[46rem] text-left text-sm">
            <thead class="bg-base-200 text-xs text-base-content/60">
              <tr>
                <.sort_th col="state" label="State" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="instance" label="Instance" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="tunnel" label="Tunnel" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="remote" label="Remote" sort_col={@sort_col} sort_dir={@sort_dir} />
                <th class="px-3 py-2 font-medium">Phase 2</th>
                <.sort_th col="uptime" label="Uptime" sort_col={@sort_col} sort_dir={@sort_dir} />
                <th class="px-3 py-2 font-medium">In / Out</th>
                <th class="px-3 py-2 font-medium"></th>
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
                      class="mr-2 inline-flex h-6 w-6 items-center justify-center rounded border border-base-content/20 text-2xl leading-none text-base-content/80 hover:bg-base-300"
                    >
                      {if MapSet.member?(@expanded, key), do: "▾", else: "▸"}
                    </button>
                    <%!-- title + sr-only text: colour must not be the only
                         carrier of up/down (a11y), the dot has no label. --%>
                    <span
                      title={if t.up, do: "Tunnel up", else: "Tunnel down"}
                      class={[
                        "inline-block h-2.5 w-2.5 rounded-full",
                        if(t.up, do: "bg-primary", else: "bg-error")
                      ]}
                    >
                      <span class="sr-only">{if t.up, do: "up", else: "down"}</span>
                    </span>
                  </td>
                  <td class="px-3 py-2">
                    <a
                      href={~p"/instances/#{t.instance_id}"}
                      class="text-base-content hover:text-primary"
                    >
                      {t.instance_name}
                    </a>
                    <.base_url_link base_url={t.base_url} />
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
                    <%!-- Configuration drift, not a fault of the tunnel: the
                         pinned local endpoint is a public address the box no
                         longer owns. Informational only — no check fires. --%>
                    <span
                      :if={t.lip_mismatch}
                      title={Orbit.Ipsec.LocalEndpoint.hint(t.local, %{ipv4: t.box_public_ip})}
                      class="ml-1 rounded bg-warning/20 px-1 py-0.5 text-[10px] text-warning"
                    >
                      local IP drift
                    </span>
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
                  <td class="px-3 py-2 text-right text-xs whitespace-nowrap">
                    <%!-- Reads, so no write role required — unlike the
                         reconnect beside them. --%>
                    <button
                      phx-click="recheck"
                      phx-value-iid={t.instance_id}
                      disabled={MapSet.member?(@busy, "recheck:#{t.instance_id}")}
                      title="Ask the box for fresh tunnel status now"
                      aria-label="Recheck tunnel status"
                      class="mr-1 rounded border border-base-content/20 p-1 align-middle text-base-content/80 hover:bg-base-300 disabled:opacity-40"
                    >
                      <Icons.icon name={:refresh} class="h-3.5 w-3.5" />
                    </button>
                    <button
                      phx-click="history_open"
                      phx-value-iid={t.instance_id}
                      phx-value-tunnel={t.id}
                      phx-value-label={t.label}
                      phx-value-up={to_string(t.up)}
                      phx-value-mode="graph"
                      title="Uptime graph"
                      aria-label="Uptime graph"
                      class="mr-1 rounded border border-base-content/20 p-1 align-middle text-base-content/80 hover:bg-base-300"
                    >
                      <Icons.icon name={:chart} class="h-3.5 w-3.5" />
                    </button>
                    <button
                      phx-click="history_open"
                      phx-value-iid={t.instance_id}
                      phx-value-tunnel={t.id}
                      phx-value-label={t.label}
                      phx-value-up={to_string(t.up)}
                      phx-value-mode="history"
                      title="Transition history"
                      aria-label="Transition history"
                      class="mr-1 rounded border border-base-content/20 p-1 align-middle text-base-content/80 hover:bg-base-300"
                    >
                      <Icons.icon name={:audit} class="h-3.5 w-3.5" />
                    </button>
                    <button
                      :if={@writable}
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
                  <td class={
                    [
                      "px-3 py-1",
                      cond do
                        # No status text pushed for this child SA — "unknown", not
                        # "down". A red "?" here alarmed operators on children of
                        # tunnels that were plainly up; muted em dash instead.
                        to_string(ch["status"]) == "" -> "text-base-content/40"
                        child_up?(ch) -> "text-primary"
                        true -> "text-error"
                      end
                    ]
                  }>
                    {if to_string(ch["status"]) == "", do: "—", else: ch["status"]}
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

        <.tunnel_history_dialog history={@history} />

        <.ping_monitor_dialog
          editor={@ping_editor}
          busy={@ping_test_busy}
          result={@ping_test}
        />
      </section>
    </main>
    """
  end

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
