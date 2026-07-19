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

  import OrbitWeb.Components.ListKit, only: [webui_link: 1, shell_link: 1, gui_open_row: 3]
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

  def handle_event("bulk", %{"action" => action}, socket) do
    cond do
      not socket.assigns.writable ->
        {:noreply, socket}

      socket.assigns.bulk_busy or MapSet.size(socket.assigns.selected) == 0 ->
        {:noreply, socket}

      true ->
        ids = MapSet.to_list(socket.assigns.selected)
        user = socket.assigns.current_user

        {:noreply,
         socket
         |> assign(bulk_busy: true, bulk_results: nil)
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
    served = Orbit.Agent.Package.served_version()

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
          update_available:
            agent_connected and served != nil and agent != nil and
              agent.agent_version != served,
          online: Instances.online?(inst),
          agent_connected: agent_connected,
          bucket: Instances.status_bucket(inst, agent_connected),
          alerts: alert_counts[inst.id] || %{crit: 0, warn: 0},
          shell_enabled: inst.shell_enabled,
          gui_openable: Orbit.GUI.openable(inst) == :ok,
          base_url: Instance.primary_base_url(inst)
        }
      end)

    assign(socket,
      instances: rows,
      served_version: served,
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
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:instances} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex flex-wrap items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:instances} class="h-5 w-5 text-base-content/60" /> Instances
            <span class="ml-2 text-sm text-base-content/60">({length(@instances)})</span>
          </h1>
          <a
            :if={@writable}
            href={~p"/instances/new"}
            class="rounded bg-primary px-2 py-1 text-xs text-white hover:bg-primary/80"
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
            bucket="all"
          />
          <.kpi_tile
            label="Online"
            value={@counts["online"] || 0}
            color="text-primary"
            active={@status_filter == "online"}
            bucket="online"
          />
          <.kpi_tile
            label="Degraded"
            value={@counts["degraded"] || 0}
            color="text-warning"
            active={@status_filter == "degraded"}
            bucket="degraded"
          />
          <.kpi_tile
            label="Offline"
            value={@counts["offline"] || 0}
            color="text-error"
            active={@status_filter == "offline"}
            bucket="offline"
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
          🛠️ {@maintenance_count} in maintenance{if @maintenance_only, do: " — showing only these"}
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
            class="ml-auto rounded-lg bg-warning px-3 py-1.5 text-sm font-medium text-white hover:bg-warning/80 disabled:opacity-50"
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
            class="ml-2 text-xs text-base-content/60 hover:text-base-content/80"
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
                  do: "bg-neutral text-base-content",
                  else: "text-base-content/70 hover:text-base-content"
                )
              ]}
            >
              {v}
            </button>
          </div>
          <div :if={@writable and MapSet.size(@selected) > 0} class="flex items-center gap-2">
            <span class="text-xs text-base-content/60">{MapSet.size(@selected)} selected:</span>
            <button
              :for={{action, label} <- @bulk_actions}
              phx-click="bulk"
              phx-value-action={action}
              data-confirm={"#{label} on #{MapSet.size(@selected)} instance(s)?"}
              disabled={@bulk_busy}
              class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/80 hover:bg-base-300 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {if @bulk_busy, do: "Running…", else: label}
            </button>
          </div>
        </div>

        <div
          :if={@bulk_results}
          class="mb-4 rounded-lg border border-base-300 bg-base-200 p-4 text-sm"
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
              class="text-xs text-base-content/60 hover:text-base-content/80"
            >
              dismiss
            </button>
          </div>
          <div :for={r <- @bulk_results} class="text-xs">
            <span class={if r.success, do: "text-primary", else: "text-error"}>
              {r.instance_name}
            </span>
            <span class="text-base-content/60"> — {r.message}</span>
          </div>
        </div>

        <div :if={@instances == []} class="text-sm text-base-content/60">
          No instances in your scope.
        </div>
        <div :if={@instances != [] and @rows == []} class="text-sm text-base-content/60">
          No matches.
        </div>

        <%!-- Grid view (InstanceCard parity, compact) --%>
        <div :if={@view == "grid" and @rows != []} class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div
            :for={i <- @rows}
            class="rounded-lg border border-base-300 bg-base-200 p-4"
          >
            <div class="flex items-center gap-2">
              <input
                :if={@writable and not i.firmware_locked}
                type="checkbox"
                phx-click="toggle_select"
                phx-value-id={i.id}
                checked={MapSet.member?(@selected, i.id)}
                class="accent-primary"
              />
              <a
                href={~p"/instances/#{i.id}"}
                class="font-medium text-base-content hover:text-primary"
              >
                {i.name}
              </a>
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
              <a
                :if={i.base_url != ""}
                href={i.base_url}
                target="_blank"
                rel="noreferrer"
                class="block truncate hover:text-base-content/70 hover:underline"
              >
                {i.base_url}
              </a>
              <div :if={i.location}>{i.location}</div>
              <div :if={i.tags != []} class="flex flex-wrap gap-1">
                <span
                  :for={t <- i.tags}
                  class="rounded bg-base-300 px-1.5 py-0.5 text-base-content/70"
                >
                  {t}
                </span>
              </div>
              <div class="text-base-content/60" title={ts_abs(i.last_success_at)}>
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
          class="overflow-x-auto rounded-lg border border-base-300"
        >
          <table class="w-full text-left text-sm">
            <thead class="bg-base-200 text-xs text-base-content/60">
              <tr>
                <th :if={@writable} class="px-3 py-2">
                  <input
                    type="checkbox"
                    phx-click="select_all"
                    checked={
                      MapSet.size(@selected) > 0 and MapSet.size(@selected) == @selectable_count
                    }
                    class="accent-primary"
                  />
                </th>
                <.sort_th col="name" label="Name" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="status" label="Status" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="location" label="Location" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="mode" label="Agent / Mode" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="tags" label="Tags" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="last_poll" label="Last poll" sort_col={@sort_col} sort_dir={@sort_dir} />
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
                    class="accent-primary"
                  />
                </td>
                <td class="px-3 py-2">
                  <a href={~p"/instances/#{i.id}"} class="text-base-content hover:text-primary">
                    {i.name}
                  </a>
                  <.webui_link instance_id={i.id} openable={i.gui_openable} />
                  <.shell_link instance_id={i.id} shell_enabled={i.shell_enabled} />
                  <.comment_editor
                    text={CommentEditor.text(@comments, i.id, "notes", "")}
                    writable={@writable}
                    instance_id={i.id}
                    kind="notes"
                  />
                  <div class="flex items-center gap-2 text-xs text-base-content/40">
                    <span>{i.device_type}</span>
                    <a
                      :if={i.base_url != ""}
                      href={i.base_url}
                      target="_blank"
                      rel="noreferrer"
                      class="truncate hover:text-base-content/70 hover:underline"
                      onclick="event.stopPropagation()"
                    >
                      {i.base_url}
                    </a>
                  </div>
                </td>
                <td class="px-3 py-2"><.status_badge row={i} /></td>
                <td class="px-3 py-2 text-base-content/70">{i.location || "—"}</td>
                <td class="px-3 py-2 text-base-content/70">
                  <span :if={i.agent_mode}>
                    agent
                    <span :if={i.agent_version} class="text-base-content/40">v{i.agent_version}</span>
                    <span
                      :if={i.update_available}
                      class="text-warning"
                      title={"update available → #{@served_version}"}
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
                <td class="px-3 py-2 text-xs text-base-content/60" title={ts_abs(i.last_success_at)}>
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
    </main>
    """
  end

  # ---- small components ------------------------------------------------------

  attr :label, :string, required: true
  attr :value, :integer, required: true
  attr :color, :string, required: true
  attr :active, :boolean, required: true
  attr :bucket, :string, required: true

  defp kpi_tile(assigns) do
    ~H"""
    <button
      phx-click="status_filter"
      phx-value-bucket={@bucket}
      class={[
        "rounded-lg border p-3 text-left",
        if(@active and @bucket != "all",
          do: "border-primary bg-base-200",
          else: "border-base-300 bg-base-200 hover:border-base-content/20"
        )
      ]}
    >
      <div class="text-xs text-base-content/60">{@label}</div>
      <div class={["text-2xl font-semibold", @color]}>{@value}</div>
    </button>
    """
  end

  attr :col, :string, required: true
  attr :label, :string, required: true
  attr :sort_col, :string, required: true
  attr :sort_dir, :atom, required: true

  defp sort_th(assigns) do
    ~H"""
    <th class="px-3 py-2 font-medium">
      <button phx-click="sort" phx-value-col={@col} class="hover:text-base-content/80">
        {@label}
        <span :if={@sort_col == @col}>{if @sort_dir == :asc, do: "↑", else: "↓"}</span>
      </button>
    </th>
    """
  end

  attr :row, :map, required: true

  defp status_badge(assigns) do
    ~H"""
    <span class="inline-flex items-center gap-1.5">
      <span class={[
        "inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs",
        badge_class(@row.bucket)
      ]}>
        <span class={["inline-block h-2 w-2 rounded-full", dot_class(@row.bucket)]}></span>
        {@row.bucket}
        <span :if={@row.maintenance} title="In maintenance — alerts capped at WARN">🛠️</span>
      </span>
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

  defp chip(true), do: "rounded-full bg-primary px-3 py-1 text-xs text-white"

  defp chip(false),
    do: "rounded-full bg-base-300 px-3 py-1 text-xs text-base-content/70 hover:bg-neutral"

  # Relative timestamp, deliberately German (fmtRelative parity — the one
  # sanctioned non-English surface, ported per plan §M5).
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
      a < 5 -> "gerade eben"
      stamp == nil -> Calendar.strftime(dt, "%Y-%m-%d")
      secs >= 0 -> "vor #{stamp}"
      true -> "in #{stamp}"
    end
  end

  defp ts_abs(nil), do: nil
  defp ts_abs(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M UTC")
end
