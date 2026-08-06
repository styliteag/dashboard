defmodule OrbitWeb.InstancesLive do
  @moduledoc """
  Instances overview — every firewall the caller may see, with live
  online/agent status. Scoped through Orbit.Instances (invariant 1); the
  agent-connected column reads the hub roster (invariant 5: filtered by the
  same scope the list already applied). Refreshes on hub roster edges + a
  30s tier timer (the standard react refetch tier).

  Interaction parity with InstancesPage.tsx: KPI tiles double as status
  filters (counted from the same buckets the row badges use, so tile
  numbers never drift from the rows), search over name/location/tags,
  device-type + tag chips, maintenance filter, sortable columns, list/grid
  toggle, and the amber "Update all agents" banner.

  Bulk actions (bulk/routes.py port): row checkboxes + an action bar for
  write roles. The handler re-checks the write gate (never trust hidden
  UI); ids outside the caller's scope are silently dropped in Orbit.Bulk.
  Actions run in start_async (firmware_check blocks up to 90s per box).
  CSV export is a sanctioned <a href> download.
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit,
    only: [
      webui_link: 1,
      shell_link: 1,
      gui_open_row: 3,
      base_url_link: 1,
      empty_state: 1,
      kpi_tile: 1
    ]

  import OrbitWeb.Components.CommentEditor, only: [comment_editor: 1]

  alias OrbitWeb.Components.CommentEditor

  alias Orbit.Audit
  alias Orbit.Bulk
  alias Orbit.Hub
  alias Orbit.Instances
  alias Orbit.Instances.Instance

  @refresh_ms 30_000
  @write_roles ~w(admin user)

  @bulk_actions [
    {"firmware_check", "Check updates"},
    {"firmware_update", "Update firmware"},
    # Bulk.run/3 has supported this all along (locked boxes skipped,
    # agent-less refused) — it simply had no entry in the menu.
    # "Major version upgrade", not the vendors' "series upgrade" jargon —
    # operators asked what a "series" is (user decision 2026-07-30).
    {"firmware_upgrade", "Major version upgrade"},
    {"ipsec_restart", "Restart IPsec"},
    {"reboot", "Reboot"}
  ]

  # Sortable columns; accessor logic mirrors INST_ACCESSORS in
  # InstancesPage.tsx (status ranks worst-first ascending).
  @sort_cols ~w(status name location mode tags last_poll)

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Orbit.PubSub, Hub.roster_topic())
      Process.send_after(self(), :refresh, @refresh_ms)
    end

    socket =
      assign(socket,
        writable: socket.assigns.current_user.role in @write_roles,
        selected: MapSet.new(),
        confirm: nil,
        confirm_typed: "",
        status_announcement: nil,
        bulk_busy: false,
        bulk_results: nil,
        search: "",
        status_filter: "all",
        type_filter: "all",
        active_tag: nil,
        maintenance_only: false,
        sort_col: "name",
        sort_dir: :asc,
        view: "list",
        update_busy: false,
        update_msg: nil
      )

    {:ok, load(socket)}
  end

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  @impl true
  def handle_event("search", %{"q" => q}, socket) do
    {:noreply, assign(socket, search: q)}
  end

  def handle_event("status_filter", %{"bucket" => b}, socket)
      when b in ~w(all online degraded offline) do
    b = if socket.assigns.status_filter == b, do: "all", else: b
    {:noreply, assign(socket, status_filter: b)}
  end

  def handle_event("type_filter", %{"type" => t}, socket) do
    t = if socket.assigns.type_filter == t, do: "all", else: t
    {:noreply, assign(socket, type_filter: t)}
  end

  # "" is the All chip; clicking the active tag clears it.
  def handle_event("tag_filter", %{"tag" => ""}, socket) do
    {:noreply, assign(socket, active_tag: nil)}
  end

  def handle_event("tag_filter", %{"tag" => tag}, socket) do
    tag = if socket.assigns.active_tag == tag, do: nil, else: tag
    {:noreply, assign(socket, active_tag: tag)}
  end

  def handle_event("toggle_maintenance", _params, socket) do
    {:noreply, assign(socket, maintenance_only: not socket.assigns.maintenance_only)}
  end

  def handle_event("sort", %{"col" => col}, socket) when col in @sort_cols do
    {col_cur, dir} = {socket.assigns.sort_col, socket.assigns.sort_dir}

    {:noreply,
     assign(socket,
       sort_col: col,
       sort_dir: if(col == col_cur and dir == :asc, do: :desc, else: :asc)
     )}
  end

  def handle_event("set_view", %{"view" => v}, socket) when v in ~w(list grid) do
    {:noreply, assign(socket, view: v)}
  end

  def handle_event("toggle_select", %{"id" => raw_id}, socket) do
    {id, ""} = Integer.parse(raw_id)
    selected = socket.assigns.selected

    selected =
      if MapSet.member?(selected, id),
        do: MapSet.delete(selected, id),
        else: MapSet.put(selected, id)

    {:noreply, assign(socket, selected: selected)}
  end

  def handle_event("select_all", _params, socket) do
    # Select what's currently visible (filtered), never firmware-locked boxes
    # (the bulk bar carries firmware actions — InstancesPage parity).
    all =
      socket.assigns
      |> visible_rows()
      |> Enum.reject(& &1.firmware_locked)
      |> MapSet.new(& &1.id)

    selected =
      if MapSet.equal?(socket.assigns.selected, all), do: MapSet.new(), else: all

    {:noreply, assign(socket, selected: selected)}
  end

  # Step 1 of the bulk flow: build the tiered confirmation. Reboot and the
  # major upgrade escalate to type-to-confirm (blast radius: every selected
  # box reboots); the dialog names the boxes (UI/UX review U-Q4/U-M5).
  def handle_event("bulk_ask", %{"action" => action}, socket)
      when action in ~w(firmware_check firmware_update firmware_upgrade ipsec_restart reboot) do
    if not socket.assigns.writable or socket.assigns.bulk_busy or
         MapSet.size(socket.assigns.selected) == 0 do
      {:noreply, socket}
    else
      names =
        socket.assigns.instances
        |> Enum.filter(&MapSet.member?(socket.assigns.selected, &1.id))
        |> Enum.map(& &1.name)
        |> Enum.sort()

      {:noreply,
       assign(socket,
         confirm: %{action: action, names: names},
         confirm_typed: ""
       )}
    end
  end

  def handle_event("confirm_typing", %{"typed" => typed}, socket),
    do: {:noreply, assign(socket, confirm_typed: typed)}

  def handle_event("bulk_cancel", _params, socket),
    do: {:noreply, assign(socket, confirm: nil, confirm_typed: "")}

  # Step 2: execute. The type-to-confirm comparison is re-checked HERE — the
  # disabled submit button in the dialog is the prompt, not the gate.
  def handle_event("bulk_run", params, socket) do
    confirm = socket.assigns.confirm

    cond do
      is_nil(confirm) or not socket.assigns.writable or socket.assigns.bulk_busy ->
        {:noreply, socket}

      bulk_tier(confirm.action) == :type_to_confirm and
          String.trim(params["typed"] || "") != to_string(length(confirm.names)) ->
        {:noreply, socket}

      true ->
        ids = MapSet.to_list(socket.assigns.selected)
        user = socket.assigns.current_user
        action = confirm.action

        {:noreply,
         socket
         |> assign(bulk_busy: true, bulk_results: nil, confirm: nil, confirm_typed: "")
         |> start_async(:bulk, fn -> Bulk.run(ids, action, user) end)}
    end
  end

  def handle_event("clear_results", _params, socket) do
    {:noreply, assign(socket, bulk_results: nil)}
  end

  # Soft-delete straight from the list (DeleteInstanceDialog parity, guarded
  # by data-confirm client-side and the write gate here — never trust the
  # hidden UI).
  def handle_event("delete", %{"id" => raw_id}, socket) do
    with true <- socket.assigns.writable,
         {id, ""} <- Integer.parse(raw_id),
         %Instance{} = inst <- Orbit.Auth.Scope.get_instance(id, socket.assigns.current_user) do
      {:ok, _} = Instances.soft_delete(inst)

      Audit.write(
        action: "instance.delete",
        result: "ok",
        user_id: socket.assigns.current_user.id,
        target_type: "instance",
        target_id: inst.id,
        detail: %{"name" => inst.name}
      )

      {:noreply, socket |> assign(selected: MapSet.new()) |> load()}
    else
      _ -> {:noreply, socket}
    end
  end

  # "Update all agents" — every connected agent whose version differs from
  # the served package, sequentially (each push blocks up to 30s).
  def handle_event("update_all", _params, socket) do
    outdated = Enum.filter(socket.assigns.instances, & &1.update_available)

    cond do
      not socket.assigns.writable or socket.assigns.update_busy or outdated == [] ->
        {:noreply, socket}

      true ->
        user = socket.assigns.current_user
        insts = Enum.map(outdated, & &1.inst)

        {:noreply,
         socket
         |> assign(update_busy: true, update_msg: nil)
         |> start_async(:update_all, fn ->
           Enum.map(insts, fn inst -> {inst.name, Orbit.Agent.Update.push(inst, user)} end)
         end)}
    end
  end

  def handle_event("clear_update_msg", _params, socket) do
    {:noreply, assign(socket, update_msg: nil)}
  end

  def handle_event("row_gui_open", %{"id" => id} = p, socket) do
    {:noreply, gui_open_row(socket, id, p["path"])}
  end

  def handle_event("comment_save", params, socket),
    do: {:noreply, socket |> CommentEditor.save(params) |> load()}

  def handle_event("comment_clear", params, socket),
    do: {:noreply, socket |> CommentEditor.clear(params) |> load()}

  @impl true
  def handle_async(:bulk, {:ok, {:ok, results}}, socket) do
    {:noreply, assign(socket, bulk_busy: false, bulk_results: results)}
  end

  def handle_async(:bulk, {:ok, {:error, :unknown_action}}, socket) do
    {:noreply, assign(socket, bulk_busy: false, bulk_results: [])}
  end

  def handle_async(:bulk, {:exit, _reason}, socket) do
    {:noreply, assign(socket, bulk_busy: false, bulk_results: [])}
  end

  def handle_async(:update_all, {:ok, results}, socket) do
    failed = for {name, {:error, msg}} <- results, do: "#{name}: #{msg}"

    msg =
      case failed do
        [] -> {:ok, "#{length(results)} update(s) pushed — agents restart"}
        _ -> {:error, "#{length(failed)} failed — " <> Enum.join(failed, "; ")}
      end

    {:noreply, socket |> assign(update_busy: false, update_msg: msg) |> load()}
  end

  def handle_async(:update_all, {:exit, _reason}, socket) do
    {:noreply, assign(socket, update_busy: false, update_msg: {:error, "update run crashed"})}
  end

  defp load(socket) do
    user = socket.assigns.current_user
    connected = Hub.list_connected()
    connected_ids = MapSet.new(connected, & &1.instance_id)
    agents = Map.new(connected, &{&1.instance_id, &1})
    # Two agent lines since the split (§28) — each row compares against the
    # served version of ITS line (device_type), never the other one's.
    served = Orbit.Agent.Package.served_versions()

    # Per-row CRIT/WARN badge — same evaluate→overlay chain as Alerts (the
    # four-surface parity rule), one pass over the caller's visible fleet.
    alert_counts =
      user
      |> Orbit.Checks.Export.evaluated(DateTime.utc_now())
      |> Map.new(fn {inst, checks} ->
        {inst.id,
         %{
           crit: Enum.count(checks, &(&1.state == 2)),
           warn: Enum.count(checks, &(&1.state == 1))
         }}
      end)

    rows =
      user
      |> Instances.list_visible()
      |> Enum.map(fn inst ->
        agent = agents[inst.id]
        agent_connected = MapSet.member?(connected_ids, inst.id)
        served_for = served[Orbit.Agent.Package.line_for(inst.device_type)]

        %{
          id: inst.id,
          inst: inst,
          name: inst.name,
          device_type: inst.device_type,
          transport: inst.transport,
          group: inst.group && inst.group.name,
          location: inst.location,
          tags: inst.tags || [],
          maintenance: inst.maintenance,
          firmware_locked: inst.firmware_locked,
          agent_mode: Instance.agent_mode?(inst),
          last_success_at: inst.last_success_at,
          agent_version: agent && agent.agent_version,
          # Short line tag for the agent cell (§28): "fw" | "linux".
          agent_line:
            if(Orbit.Agent.Package.line_for(inst.device_type) == :linux, do: "linux", else: "fw"),
          served_version: served_for,
          update_available:
            agent_connected and served_for != nil and agent != nil and
              agent.agent_version != served_for,
          online: Instances.online?(inst),
          agent_connected: agent_connected,
          bucket: Instances.status_bucket(inst, agent_connected),
          alerts: alert_counts[inst.id] || %{crit: 0, warn: 0},
          shell_enabled: inst.shell_enabled,
          gui_openable: Orbit.GUI.openable(inst) == :ok,
          base_url: inst.base_url || "",
          # Fleet policy is NO password on the console menu, so a box that
          # reports one is the exception worth seeing. The detail page has
          # said so for a while; from the list there was no way to tell which
          # boxes deviate without opening each one.
          console_pw:
            get_in(Hub.cache_entry(inst.id), [
              "status",
              "system",
              "console_password_protected"
            ]) == true
        }
      end)

    # Banner label: one value while both lines serve the same version,
    # otherwise name them ("fw 3.2.0 · linux 3.2.1").
    served_label =
      case served |> Map.values() |> Enum.reject(&is_nil/1) |> Enum.uniq() do
        [] -> nil
        [v] -> v
        _ -> "fw #{served.firewall || "—"} · linux #{served.linux || "—"}"
      end

    # Screen readers never hear a LiveView patch flip a box offline (UI/UX
    # review A-M6) — diff the status buckets against the previous load and
    # voice only real transitions into the sr-only aria-live region.
    # Coalesced into one sentence per refresh; unchanged text is not
    # re-announced, so quiet refreshes stay silent.
    old_buckets = Map.new(socket.assigns[:instances] || [], &{&1.id, &1.bucket})

    changes =
      for row <- rows,
          old = old_buckets[row.id],
          old != nil and old != row.bucket,
          do: "#{row.name} is now #{row.bucket}"

    socket =
      if changes == [],
        do: socket,
        else: assign(socket, status_announcement: Enum.join(changes, "; "))

    assign(socket,
      instances: rows,
      served_version: served_label,
      comments: CommentEditor.lookup(Enum.map(rows, & &1.inst))
    )
  end

  # ---- filtering + sorting --------------------------------------------------

  defp visible_rows(a) do
    a.instances
    |> Enum.filter(&matches_search(&1, String.downcase(a.search)))
    |> Enum.filter(&(a.status_filter == "all" or &1.bucket == a.status_filter))
    |> Enum.filter(&(a.type_filter == "all" or &1.device_type == a.type_filter))
    |> Enum.filter(&(a.active_tag == nil or a.active_tag in &1.tags))
    |> Enum.filter(&(not a.maintenance_only or &1.maintenance))
    |> sort_rows(a.sort_col, a.sort_dir)
  end

  defp matches_search(_row, ""), do: true

  defp matches_search(row, q) do
    String.contains?(String.downcase(row.name), q) or
      String.contains?(String.downcase(row.location || ""), q) or
      Enum.any?(row.tags, &String.contains?(String.downcase(&1), q))
  end

  defp sort_rows(rows, col, dir) do
    Enum.sort_by(rows, sort_key(col), dir)
  end

  defp sort_key("status"), do: fn r -> status_rank(r) end
  defp sort_key("name"), do: fn r -> String.downcase(r.name) end
  defp sort_key("location"), do: fn r -> String.downcase(r.location || "") end
  defp sort_key("mode"), do: fn r -> if r.agent_mode, do: "agent", else: "api" end
  defp sort_key("tags"), do: fn r -> r.tags |> Enum.join(",") |> String.downcase() end

  defp sort_key("last_poll") do
    fn r -> (r.last_success_at && DateTime.to_unix(r.last_success_at)) || 0 end
  end

  defp status_rank(%{bucket: "offline"}), do: 0
  defp status_rank(%{bucket: "degraded"}), do: 1
  defp status_rank(_), do: 2

  # ---- render ----------------------------------------------------------------

  @impl true
  def render(assigns) do
    rows = visible_rows(assigns)

    assigns =
      assign(assigns,
        bulk_actions: @bulk_actions,
        rows: rows,
        counts: Enum.frequencies_by(assigns.instances, & &1.bucket),
        all_tags: assigns.instances |> Enum.flat_map(& &1.tags) |> Enum.uniq() |> Enum.sort(),
        present_types:
          assigns.instances |> Enum.map(& &1.device_type) |> Enum.uniq() |> Enum.sort(),
        maintenance_count: Enum.count(assigns.instances, & &1.maintenance),
        outdated_count: Enum.count(assigns.instances, & &1.update_available),
        selectable_count: Enum.count(rows, &(not &1.firmware_locked))
      )

    ~H"""
    <main id="main" class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:instances} current_user={@current_user} />
      <p :if={@status_announcement} aria-live="polite" class="sr-only">
        {@status_announcement}
      </p>

      <section class="p-6">
        <div class="mb-4 flex flex-wrap items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:instances} class="h-5 w-5 text-base-content/70" /> Instances
            <span class="ml-2 text-sm text-base-content/70">({length(@instances)})</span>
          </h1>
          <a
            :if={@writable}
            href={~p"/instances/new"}
            class="rounded bg-primary px-2 py-1 text-xs text-primary-content hover:bg-primary/80"
          >
            New instance
          </a>
          <a
            href={~p"/api/export/instances.csv"}
            class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
          >
            Export CSV
          </a>
        </div>

        <%!-- KPI tiles double as status filter (US-3.4 / KpiTile parity);
             counted from the row buckets so tiles and badges can't drift. --%>
        <div class="mb-4 grid gap-3 sm:grid-cols-4">
          <.kpi_tile
            label="Total"
            value={length(@instances)}
            color="text-base-content"
            active={@status_filter == "all"}
            event="status_filter"
            value_name="all"
          />
          <.kpi_tile
            label="Online"
            value={@counts["online"] || 0}
            color="text-primary"
            active={@status_filter == "online"}
            event="status_filter"
            value_name="online"
          />
          <.kpi_tile
            label="Degraded"
            value={@counts["degraded"] || 0}
            color="text-warning"
            active={@status_filter == "degraded"}
            event="status_filter"
            value_name="degraded"
          />
          <.kpi_tile
            label="Offline"
            value={@counts["offline"] || 0}
            color="text-error"
            active={@status_filter == "offline"}
            event="status_filter"
            value_name="offline"
          />
        </div>

        <button
          :if={@maintenance_count > 0}
          phx-click="toggle_maintenance"
          class={[
            "mb-3 inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs",
            if(@maintenance_only,
              do: "border-warning bg-warning/20 text-warning",
              else: "border-warning/40 bg-warning/10 text-warning hover:bg-warning/20"
            )
          ]}
        >
          <Icons.icon name={:maintenance} class="mr-1 inline h-3.5 w-3.5" />{@maintenance_count} in maintenance{if @maintenance_only,
            do: " — showing only these"}
        </button>

        <%!-- Update-all banner (agents behind the served package). --%>
        <div
          :if={@outdated_count > 0}
          class="mb-4 flex flex-wrap items-center gap-3 rounded-lg border border-warning/40 bg-warning/10 px-4 py-2.5"
        >
          <span class="text-sm text-warning">
            {@outdated_count} agent{if @outdated_count > 1, do: "s"} can be updated{if @served_version,
              do: " → #{@served_version}"}
          </span>
          <button
            :if={@writable}
            phx-click="update_all"
            data-confirm={"Push agent #{@served_version} to #{@outdated_count} box(es)? Agents restart."}
            disabled={@update_busy}
            class="ml-auto rounded-lg bg-warning px-3 py-1.5 text-sm font-medium text-warning-content hover:bg-warning/80 disabled:opacity-50"
          >
            {if @update_busy, do: "Updating…", else: "Update all agents"}
          </button>
        </div>
        <div
          :if={@update_msg}
          class={[
            "mb-3 rounded-lg px-3 py-2 text-sm",
            case @update_msg do
              {:ok, _} -> "bg-warning/15 text-warning"
              _ -> "bg-error/15 text-error"
            end
          ]}
        >
          {elem(@update_msg, 1)}
          <button
            phx-click="clear_update_msg"
            class="ml-2 text-xs text-base-content/70 hover:text-base-content/80"
          >
            dismiss
          </button>
        </div>

        <%!-- Search + type/tag chips + view toggle --%>
        <form phx-change="search" onsubmit="return false" class="mb-3 max-w-md">
          <input
            type="text"
            name="q"
            value={@search}
            placeholder="Search by name, location, tag…"
            phx-debounce="300"
            class="w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </form>

        <div :if={length(@present_types) > 1} class="mb-3 flex flex-wrap gap-2">
          <button
            phx-click="type_filter"
            phx-value-type="all"
            class={chip(@type_filter == "all")}
          >
            All types
          </button>
          <button
            :for={t <- @present_types}
            phx-click="type_filter"
            phx-value-type={t}
            class={chip(@type_filter == t)}
          >
            {t}
          </button>
        </div>

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

        <div class="mb-4 flex items-center justify-between">
          <div class="inline-flex rounded-lg border border-base-content/20 bg-base-300/50 p-0.5 text-xs">
            <button
              :for={v <- ~w(list grid)}
              phx-click="set_view"
              phx-value-view={v}
              class={[
                "rounded-md px-3 py-1.5 capitalize",
                if(@view == v,
                  do: "bg-neutral text-neutral-content",
                  else: "text-base-content/70 hover:text-base-content"
                )
              ]}
            >
              {v}
            </button>
            <%!-- Third "view" of the same fleet — navigates to /uptime
                 rather than toggling, so it is never the active segment. --%>
            <.link
              navigate={~p"/uptime"}
              class="rounded-md px-3 py-1.5 text-base-content/70 hover:text-base-content"
            >
              Uptime
            </.link>
          </div>
          <div :if={@writable and MapSet.size(@selected) > 0} class="flex items-center gap-2">
            <span class="text-xs text-base-content/70">{MapSet.size(@selected)} selected:</span>
            <%!-- No data-confirm here: the bulk dialog must name the boxes
                 and escalate with blast radius (UI/UX review U-Q4/U-M5) —
                 native confirm() rendered "Reboot" identical to "Check
                 updates". bulk_ask builds the tiered confirm_dialog. --%>
            <button
              :for={{action, label} <- @bulk_actions}
              phx-click="bulk_ask"
              phx-value-action={action}
              disabled={@bulk_busy}
              class={[
                "rounded border px-2 py-1 text-xs disabled:cursor-not-allowed disabled:opacity-40",
                if(action in ~w(firmware_upgrade reboot),
                  do: "border-error/40 text-error hover:bg-error/15",
                  else: "border-base-content/20 text-base-content/80 hover:bg-base-300"
                )
              ]}
            >
              {if @bulk_busy, do: "Running…", else: label}
            </button>
          </div>
        </div>

        <div
          :if={@bulk_results}
          class="mb-4 rounded-[var(--radius-box)] border border-base-300 bg-base-200 p-4 text-sm"
        >
          <div class="mb-2 flex items-center gap-3">
            <span class="text-base-content/80">
              Bulk result: {Enum.count(@bulk_results, & &1.success)} ok, {Enum.count(
                @bulk_results,
                &(not &1.success)
              )} failed
            </span>
            <button
              phx-click="clear_results"
              class="text-xs text-base-content/70 hover:text-base-content/80"
            >
              dismiss
            </button>
          </div>
          <div :for={r <- @bulk_results} class="text-xs">
            <span class={if r.success, do: "text-primary", else: "text-error"}>
              {r.instance_name}
            </span>
            <span class="text-base-content/70"> — {r.message}</span>
          </div>
        </div>

        <%!-- Zero instances conflated "fresh install" with "account has no
             group" and offered no next step (UI/UX review U-Q5). --%>
        <.empty_state :if={@instances == []} title="No instances visible for your account.">
          Either none exist yet, or your account is in no group — group membership
          decides what you can see; ask a superadmin if you expected instances here.
          <:action :if={@writable}>
            <a
              href={~p"/instances/new"}
              class="rounded bg-primary px-3 py-1.5 text-sm text-primary-content hover:bg-primary/80"
            >
              New instance
            </a>
          </:action>
        </.empty_state>
        <div :if={@instances != [] and @rows == []} class="text-sm text-base-content/70">
          No matches.
        </div>

        <%!-- Grid view (InstanceCard parity, compact) --%>
        <div :if={@view == "grid" and @rows != []} class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div
            :for={i <- @rows}
            class="rounded-[var(--radius-box)] border border-base-300 bg-base-200 p-4 transition-colors hover:border-base-content/20"
          >
            <div class="flex items-center gap-2">
              <input
                :if={@writable and not i.firmware_locked}
                type="checkbox"
                phx-click="toggle_select"
                phx-value-id={i.id}
                checked={MapSet.member?(@selected, i.id)}
                aria-label={"Select #{i.name}"}
                class="accent-primary"
              />
              <a
                href={~p"/instances/#{i.id}"}
                class="font-medium text-base-content hover:text-primary"
              >
                {i.name}
              </a>
              <.base_url_link base_url={i.base_url} />
              <.webui_link instance_id={i.id} openable={i.gui_openable} />
              <.shell_link instance_id={i.id} shell_enabled={i.shell_enabled} />
              <.comment_editor
                text={CommentEditor.text(@comments, i.id, "notes", "")}
                writable={@writable}
                instance_id={i.id}
                kind="notes"
              />
              <.status_badge row={i} />
            </div>
            <div class="mt-2 space-y-1 text-xs text-base-content/70">
              <div>{i.device_type} · {if i.agent_mode, do: "agent", else: "api"}</div>
              <div :if={i.base_url != ""} class="truncate">
                <.base_url_links base_url={i.base_url} class="hover:text-base-content/70" />
              </div>
              <div :if={i.location}>{i.location}</div>
              <div :if={i.tags != []} class="flex flex-wrap gap-1">
                <span
                  :for={t <- i.tags}
                  class="rounded bg-base-300 px-1.5 py-0.5 text-base-content/70"
                >
                  {t}
                </span>
              </div>
              <div class="text-base-content/70" title={ts_abs(i.last_success_at)}>
                {ts_rel(i.last_success_at)}
              </div>
            </div>
            <div :if={@writable} class="mt-3 flex gap-2 text-xs">
              <a
                href={~p"/instances/#{i.id}/edit"}
                class="text-base-content/70 hover:text-base-content"
              >
                Edit
              </a>
              <button
                phx-click="delete"
                phx-value-id={i.id}
                data-confirm={"Delete #{i.name}? The instance is soft-deleted and disappears from all views."}
                class="text-error/70 hover:text-error"
              >
                Delete
              </button>
            </div>
          </div>
        </div>

        <%!-- List view --%>
        <div
          :if={@view == "list" and @rows != []}
          class="overflow-x-auto rounded-[var(--radius-box)] border border-base-300"
        >
          <table class="w-full min-w-[46rem] text-left text-sm">
            <thead class="bg-base-200 text-xs text-base-content/70">
              <tr>
                <th :if={@writable} class="px-3 py-2">
                  <input
                    type="checkbox"
                    phx-click="select_all"
                    checked={
                      MapSet.size(@selected) > 0 and MapSet.size(@selected) == @selectable_count
                    }
                    aria-label="Select all instances"
                    class="accent-primary"
                  />
                </th>
                <.sort_th col="name" label="Name" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="status" label="Status" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="location" label="Location" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="mode" label="Agent / Mode" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="tags" label="Tags" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th
                  col="last_poll"
                  label="Last poll"
                  sort_col={@sort_col}
                  sort_dir={@sort_dir}
                />
                <th :if={@writable} class="px-3 py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={i <- @rows} class="border-b border-base-300/50 last:border-0">
                <td :if={@writable} class="px-3 py-2">
                  <input
                    :if={not i.firmware_locked}
                    type="checkbox"
                    phx-click="toggle_select"
                    phx-value-id={i.id}
                    checked={MapSet.member?(@selected, i.id)}
                    aria-label={"Select #{i.name}"}
                    class="accent-primary"
                  />
                </td>
                <td class="px-3 py-2">
                  <a href={~p"/instances/#{i.id}"} class="text-base-content hover:text-primary">
                    {i.name}
                  </a>
                  <.base_url_link base_url={i.base_url} />
                  <.webui_link instance_id={i.id} openable={i.gui_openable} />
                  <.shell_link instance_id={i.id} shell_enabled={i.shell_enabled} />
                  <.comment_editor
                    text={CommentEditor.text(@comments, i.id, "notes", "")}
                    writable={@writable}
                    instance_id={i.id}
                    kind="notes"
                  />
                  <div class="flex items-center gap-2 text-xs text-base-content/70">
                    <span>{i.device_type}</span>
                    <div :if={i.base_url != ""} class="truncate">
                      <.base_url_links
                        base_url={i.base_url}
                        class="hover:text-base-content/70"
                        onclick="event.stopPropagation()"
                      />
                    </div>
                  </div>
                </td>
                <td class="px-3 py-2"><.status_badge row={i} /></td>
                <td class="px-3 py-2 text-base-content/70">{i.location || "—"}</td>
                <td class="px-3 py-2 text-base-content/70">
                  <span :if={i.agent_mode} title={"agent line: #{i.agent_line}"}>
                    agent <span class="text-base-content/70">{i.agent_line}</span>
                    <span :if={i.agent_version} class="text-base-content/70">v{i.agent_version}</span>
                    <span
                      :if={i.update_available}
                      class="text-warning"
                      title={"update available → #{i.served_version}"}
                    >
                      ↑
                    </span>
                  </span>
                  <span :if={not i.agent_mode}>{i.transport}</span>
                </td>
                <td class="px-3 py-2">
                  <div class="flex flex-wrap gap-1">
                    <span
                      :for={t <- i.tags}
                      class="rounded bg-base-300 px-1.5 py-0.5 text-xs text-base-content/70"
                    >
                      {t}
                    </span>
                  </div>
                </td>
                <td class="px-3 py-2 text-xs text-base-content/70" title={ts_abs(i.last_success_at)}>
                  {ts_rel(i.last_success_at)}
                </td>
                <td :if={@writable} class="px-3 py-2 text-xs">
                  <a
                    href={~p"/instances/#{i.id}/edit"}
                    class="text-base-content/70 hover:text-base-content"
                  >
                    Edit
                  </a>
                  <button
                    phx-click="delete"
                    phx-value-id={i.id}
                    data-confirm={"Delete #{i.name}? The instance is soft-deleted and disappears from all views."}
                    class="ml-2 text-error/70 hover:text-error"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
      <.confirm_dialog
        :if={@confirm}
        title={bulk_title(@confirm.action, length(@confirm.names))}
        tier={bulk_tier(@confirm.action)}
        confirm_label={bulk_title(@confirm.action, length(@confirm.names))}
        on_confirm="bulk_run"
        on_cancel="bulk_cancel"
        typed={@confirm_typed}
        must_type={to_string(length(@confirm.names))}
        items={@confirm.names}
      >
        {bulk_consequence(@confirm.action, length(@confirm.names))}
      </.confirm_dialog>
    </main>
    """
  end

  # The dialog copy states the consequence, not just the action; reboot and
  # the major upgrade require typing the box COUNT (typing 12 names is not
  # a safeguard, it is a punishment).
  defp bulk_tier(a) when a in ~w(firmware_upgrade reboot), do: :type_to_confirm
  defp bulk_tier("firmware_check"), do: :info
  defp bulk_tier(_), do: :danger

  defp bulk_title("firmware_check", n), do: "Check updates on #{n} instance(s)"
  defp bulk_title("firmware_update", n), do: "Update firmware on #{n} instance(s)"
  defp bulk_title("firmware_upgrade", n), do: "Major version upgrade on #{n} instance(s)"
  defp bulk_title("ipsec_restart", n), do: "Restart IPsec on #{n} instance(s)"
  defp bulk_title("reboot", n), do: "Reboot #{n} instance(s)"

  defp bulk_consequence("firmware_check", _n),
    do: "Runs an update check on the selected boxes. Nothing is installed."

  defp bulk_consequence("firmware_update", _n),
    do: "Firmware updates start immediately on all selected boxes; some may reboot to apply."

  defp bulk_consequence("firmware_upgrade", n),
    do:
      "Major version jump — every selected box downloads, installs and REBOOTS; not undoable from here. Type #{n} to confirm."

  defp bulk_consequence("ipsec_restart", _n),
    do: "All IPsec tunnels on the selected boxes drop and re-establish."

  defp bulk_consequence("reboot", n),
    do: "All selected boxes go down for a couple of minutes. Type #{n} to confirm."

  # ---- small components ------------------------------------------------------

  attr :col, :string, required: true
  attr :label, :string, required: true
  attr :sort_col, :string, required: true
  attr :sort_dir, :atom, required: true

  defp sort_th(assigns) do
    ~H"""
    <th
      scope="col"
      aria-sort={
        if @sort_col == @col,
          do: if(@sort_dir == :asc, do: "ascending", else: "descending"),
          else: "none"
      }
      class="px-3 py-2 font-medium"
    >
      <button phx-click="sort" phx-value-col={@col} class="hover:text-base-content/80">
        {@label}
        <span :if={@sort_col == @col} aria-hidden="true">{if @sort_dir == :asc, do: "↑", else: "↓"}</span>
      </button>
    </th>
    """
  end

  attr :row, :map, required: true

  defp status_badge(assigns) do
    ~H"""
    <span class="inline-flex items-center gap-1.5">
      <%!-- The status was the one thing on the row that looked clickable and
           was not. It goes where the status comes from: the box's own page. --%>
      <.link
        navigate={~p"/instances/#{@row.id}"}
        title={"#{@row.name} is #{@row.bucket} — open the instance"}
        class={[
          "inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs hover:brightness-125",
          badge_class(@row.bucket)
        ]}
      >
        <span class={["inline-block h-2 w-2 rounded-full", dot_class(@row.bucket)]}></span>
        {@row.bucket}
        <span :if={@row.maintenance} title="In maintenance — alerts capped at WARN">
          <Icons.icon name={:maintenance} class="inline h-3 w-3" />
          <span class="sr-only">in maintenance</span>
        </span>
      </.link>
      <%!-- Deviation from the fleet standard (no console password), so it is
           a warning, not a capability chip. --%>
      <a
        :if={@row.console_pw}
        href={~p"/instances/#{@row.id}"}
        title="Console password protection is enabled on this box — fleet standard is no password on the console menu."
        class="rounded bg-warning/20 px-1.5 py-0.5 text-xs text-warning"
      >
        Console PW
      </a>
      <a
        :if={@row.alerts.crit > 0 or @row.alerts.warn > 0}
        href={~p"/alerts?q=#{@row.name}"}
        class={[
          "rounded px-1.5 py-0.5 text-xs",
          if(@row.alerts.crit > 0,
            do: "bg-error/20 text-error",
            else: "bg-warning/20 text-warning"
          )
        ]}
        title={"#{@row.alerts.crit} CRIT, #{@row.alerts.warn} WARN service check(s) — view in Alerts"}
      >
        {if @row.alerts.crit > 0,
          do: "#{@row.alerts.crit} CRIT",
          else: "#{@row.alerts.warn} WARN"}
      </a>
    </span>
    """
  end

  defp badge_class("online"), do: "bg-primary/15 text-primary"
  defp badge_class("degraded"), do: "bg-warning/15 text-warning"
  defp badge_class(_), do: "bg-error/15 text-error"

  defp dot_class("online"), do: "bg-primary"
  defp dot_class("degraded"), do: "bg-warning"
  defp dot_class(_), do: "bg-error"

  defp chip(true), do: "rounded-full bg-primary px-3 py-1 text-xs text-primary-content"

  defp chip(false),
    do:
      "rounded-full bg-base-300 px-3 py-1 text-xs text-base-content/70 hover:bg-neutral hover:text-neutral-content"

  # Relative timestamp. English since 2026-07-20 (user decision) — the old
  # fmtRelative German ("vor 14s") was the React era's one sanctioned
  # non-English surface and read inconsistent inside the English UI.
  defp ts_rel(nil), do: "—"

  defp ts_rel(%DateTime{} = dt) do
    secs = DateTime.diff(DateTime.utc_now(), dt)
    a = abs(secs)

    stamp =
      cond do
        a < 5 -> nil
        a < 60 -> "#{a}s"
        a < 3_600 -> "#{div(a, 60)}min"
        a < 86_400 -> "#{div(a, 3_600)}h"
        a < 2_592_000 -> "#{div(a, 86_400)}d"
        true -> nil
      end

    cond do
      a < 5 -> "just now"
      stamp == nil -> local_time_tag(dt, "date")
      secs >= 0 -> "#{stamp} ago"
      true -> "in #{stamp}"
    end
  end

  defp ts_abs(nil), do: nil
  defp ts_abs(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M UTC")
end
