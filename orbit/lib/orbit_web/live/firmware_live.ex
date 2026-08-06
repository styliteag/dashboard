defmodule OrbitWeb.FirmwareLive do
  @moduledoc """
  Fleet firmware compliance — current version + pending-update state per
  visible instance, read from the hub section cache (raw firmware section).
  The update verdict uses the same firmware check family (security ⇒ WARN,
  routine ⇒ ok-but-counted, failed check ⇒ WARN), so it agrees with Alerts
  and the exports. Scoped through the instance list (invariant 5); roster-edge
  PubSub + 60s tier timer (firmware moves slowly).

  Interaction parity with FirmwareCompliancePage.tsx: KPI tiles as verdict
  filters, search, device-type chips, sortable columns, latest/security/
  needs-reboot/location columns, lock indicator and quick links. Bulk
  update/series-upgrade (row checkboxes + action buttons) mirror the old
  page's eligibility rules: only unlocked boxes with a pending update are
  selectable, series upgrades additionally need agent mode and an on-box
  resolved target version. The handler re-checks the write gate (never
  trust hidden UI); ids outside the caller's scope are silently dropped in
  Orbit.Bulk.
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit
  import OrbitWeb.Components.CommentEditor, only: [comment_editor: 1]

  alias Orbit.Bulk
  alias Orbit.Checks.Evaluate
  alias Orbit.Hub
  alias Orbit.Instances
  alias Orbit.Instances.Instance
  alias OrbitWeb.Components.CommentEditor

  @refresh_ms 60_000
  @sort_cols ~w(state instance version latest location)

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
       type_filter: "all",
       sort_col: "state",
       sort_dir: :asc,
       selected: MapSet.new(),
       confirm: nil,
       confirm_typed: "",
       bulk_busy: false,
       bulk_results: nil,
       writable: socket.assigns.current_user.role in ~w(admin user)
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

  def handle_event("state_filter", %{"bucket" => b}, socket)
      when b in ~w(all ok update unknown) do
    b = if socket.assigns.state_filter == b, do: "all", else: b
    {:noreply, assign(socket, state_filter: b)}
  end

  def handle_event("type_filter", %{"type" => t}, socket) do
    t = if socket.assigns.type_filter == t, do: "all", else: t
    {:noreply, assign(socket, type_filter: t)}
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
    # Select what's currently visible AND update-eligible — filtering down
    # never selects hidden rows, locked/up-to-date boxes stay untouchable.
    all =
      socket.assigns
      |> visible()
      |> Enum.filter(&eligible?/1)
      |> MapSet.new(& &1.id)

    selected =
      if MapSet.equal?(socket.assigns.selected, all), do: MapSet.new(), else: all

    {:noreply, assign(socket, selected: selected)}
  end

  # Step 1: build the tiered confirmation (UI/UX review U-M5 — the BULK
  # major upgrade had a plain native confirm while the single-box one had
  # type-to-confirm: protection inverse to blast radius).
  def handle_event("bulk_ask", %{"action" => action}, socket)
      when action in ~w(firmware_update firmware_upgrade) do
    names = bulk_target_names(socket.assigns, action)

    if not socket.assigns.writable or socket.assigns.bulk_busy or names == [] do
      {:noreply, socket}
    else
      {:noreply, assign(socket, confirm: %{action: action, names: names}, confirm_typed: "")}
    end
  end

  def handle_event("confirm_typing", %{"typed" => typed}, socket),
    do: {:noreply, assign(socket, confirm_typed: typed)}

  def handle_event("bulk_cancel", _params, socket),
    do: {:noreply, assign(socket, confirm: nil, confirm_typed: "")}

  # Step 2: execute. The typed count is re-verified HERE for the upgrade —
  # the disabled dialog button is the prompt, not the gate.
  def handle_event("bulk_run", params, socket) do
    confirm = socket.assigns.confirm

    targets =
      confirm && bulk_targets(visible(socket.assigns), socket.assigns.selected, confirm.action)

    cond do
      is_nil(confirm) or not socket.assigns.writable or socket.assigns.bulk_busy or
          targets == [] ->
        {:noreply, socket}

      confirm.action == "firmware_upgrade" and
          String.trim(params["typed"] || "") != to_string(length(confirm.names)) ->
        {:noreply, socket}

      true ->
        user = socket.assigns.current_user
        action = confirm.action

        {:noreply,
         socket
         |> assign(bulk_busy: true, bulk_results: nil, confirm: nil, confirm_typed: "")
         |> start_async(:bulk, fn -> Bulk.run(targets, action, user) end)}
    end
  end

  def handle_event("clear_results", _params, socket) do
    {:noreply, assign(socket, bulk_results: nil)}
  end

  def handle_event("comment_save", params, socket),
    do: {:noreply, socket |> CommentEditor.save(params) |> load()}

  def handle_event("comment_clear", params, socket),
    do: {:noreply, socket |> CommentEditor.clear(params) |> load()}

  @impl true
  def handle_async(:bulk, {:ok, {:ok, results}}, socket) do
    # Selection is spent — FirmwareCompliancePage parity, and it prevents an
    # accidental double-fire on the same boxes from the still-open bar.
    {:noreply, assign(socket, bulk_busy: false, bulk_results: results, selected: MapSet.new())}
  end

  def handle_async(:bulk, {:ok, {:error, :unknown_action}}, socket) do
    {:noreply, assign(socket, bulk_busy: false, bulk_results: [])}
  end

  def handle_async(:bulk, {:exit, _reason}, socket) do
    {:noreply, assign(socket, bulk_busy: false, bulk_results: [])}
  end

  defp load(socket) do
    # Firmware state is reported by polled boxes too (Securepoint sends a
    # version); filtering to agent-mode hid them from the compliance view.
    instances = Instances.list_visible(socket.assigns.current_user)

    rows =
      Enum.map(instances, fn inst ->
        fw = Hub.cache_entry(inst.id)["firmware"] || %{}
        check = fw != %{} && Evaluate.firmware_check(fw)

        %{
          id: inst.id,
          name: inst.name,
          device_type: inst.device_type,
          location: inst.location || "",
          firmware_locked: inst.firmware_locked,
          shell_enabled: inst.shell_enabled,
          gui_openable: Orbit.GUI.openable(inst) == :ok,
          base_url: Instance.primary_base_url(inst),
          agent_mode: Instance.agent_mode?(inst),
          version: fw["product_version"] || "—",
          latest: fw["product_latest"] || "",
          upgrade_available: fw["upgrade_available"] == true,
          upgrade_major_version: fw["upgrade_major_version"],
          security_updates: fw["security_updates"] || 0,
          needs_reboot: fw["needs_reboot"] == true,
          state: (check && check.state) || 3,
          # The box tried to check for updates and the check itself failed —
          # "no answer", not "an update is waiting". The check engine rates it
          # WARN (unchanged, so Alerts/Checkmk/Prometheus keep agreeing); this
          # page buckets it under Unknown, where "we do not know" belongs.
          check_failed: fw["check_failed"] == true,
          summary: (check && check.summary) || "No firmware data"
        }
      end)

    assign(socket, rows: rows, comments: CommentEditor.lookup(instances))
  end

  @doc """
  Compliance bucket for a row — deliberately not the check state.

  A failed update check is WARN in the check engine (and must stay WARN, or
  Alerts, Checkmk and Prometheus would stop agreeing with each other), but for
  compliance counting "the box could not ask" is Unknown, not "an update is
  waiting". Public only so the mapping is unit-testable.
  """
  def bucket(%{check_failed: true}), do: "unknown"
  def bucket(%{state: 0}), do: "ok"
  def bucket(%{state: s}) when s in [1, 2], do: "update"
  def bucket(_), do: "unknown"

  @doc """
  Bulk-update eligibility (FirmwareCompliancePage parity): only a box with a
  pending update that is not firmware-locked may be selected. Public only so
  the rules are unit-testable.
  """
  def eligible?(row), do: row.upgrade_available and not row.firmware_locked

  @doc """
  Series/major upgrades additionally need an agent on the box (the target is
  resolved on-box; direct-poll instances keep using the vendor GUI) and a
  reported target version.
  """
  def series_eligible?(row) do
    eligible?(row) and row.agent_mode and (row.upgrade_major_version || "") != ""
  end

  @doc """
  Ids to act on: the intersection of the selection and the currently visible
  eligible rows — filtering down never fires updates on hidden instances,
  and a stale selection (row no longer eligible) is dropped, not acted on.
  """
  def bulk_targets(rows, selected, action) do
    eligible = if action == "firmware_upgrade", do: &series_eligible?/1, else: &eligible?/1

    rows
    |> Enum.filter(eligible)
    |> Enum.filter(&MapSet.member?(selected, &1.id))
    |> Enum.map(& &1.id)
  end

  defp visible(a) do
    q = String.downcase(a.search)

    a.rows
    |> Enum.filter(fn r ->
      q == "" or
        String.contains?(String.downcase(r.name), q) or
        String.contains?(String.downcase(r.version), q) or
        String.contains?(String.downcase(r.location), q)
    end)
    |> Enum.filter(&(a.state_filter == "all" or bucket(&1) == a.state_filter))
    |> Enum.filter(&(a.type_filter == "all" or &1.device_type == a.type_filter))
    |> Enum.sort_by(sort_key(a.sort_col), a.sort_dir)
  end

  defp sort_key("state") do
    fn r -> {-Orbit.Checks.ServiceCheck.severity(r.state), String.downcase(r.name)} end
  end

  defp sort_key("instance"), do: fn r -> String.downcase(r.name) end
  defp sort_key("version"), do: fn r -> r.version end
  defp sort_key("latest"), do: fn r -> r.latest end
  defp sort_key("location"), do: fn r -> String.downcase(r.location) end

  @impl true
  def render(assigns) do
    visible_rows = visible(assigns)
    eligible_ids = visible_rows |> Enum.filter(&eligible?/1) |> MapSet.new(& &1.id)
    series_ids = visible_rows |> Enum.filter(&series_eligible?/1) |> MapSet.new(& &1.id)

    assigns =
      assign(assigns,
        visible_rows: visible_rows,
        all_eligible_selected:
          MapSet.size(eligible_ids) > 0 and MapSet.subset?(eligible_ids, assigns.selected),
        selected_update_count: MapSet.size(MapSet.intersection(assigns.selected, eligible_ids)),
        selected_series_count: MapSet.size(MapSet.intersection(assigns.selected, series_ids)),
        ok_count: Enum.count(assigns.rows, &(bucket(&1) == "ok")),
        update_count: Enum.count(assigns.rows, &(bucket(&1) == "update")),
        unknown_count: Enum.count(assigns.rows, &(bucket(&1) == "unknown")),
        present_types: assigns.rows |> Enum.map(& &1.device_type) |> Enum.uniq() |> Enum.sort()
      )

    ~H"""
    <main id="main" class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:firmware} current_user={@current_user} />

      <section class="p-6">
        <h1 class="flex items-center gap-2 mb-4 text-lg font-medium text-base-content">
          <Icons.icon name={:firmware} class="h-5 w-5 text-base-content/60" /> Firmware
          <span class="ml-2 text-sm text-base-content/60">({length(@rows)})</span>
        </h1>

        <div class="mb-4 grid gap-3 sm:grid-cols-4">
          <.kpi_tile
            label="Total"
            value={length(@rows)}
            event="state_filter"
            value_name="all"
            active={@state_filter == "all"}
          />
          <.kpi_tile
            label="Up to date"
            value={@ok_count}
            color="text-primary"
            event="state_filter"
            value_name="ok"
            active={@state_filter == "ok"}
          />
          <.kpi_tile
            label="Update available"
            value={@update_count}
            color="text-warning"
            event="state_filter"
            value_name="update"
            active={@state_filter == "update"}
          />
          <.kpi_tile
            label="Unknown"
            value={@unknown_count}
            color="text-base-content/70"
            event="state_filter"
            value_name="unknown"
            active={@state_filter == "unknown"}
          />
        </div>

        <div class="mb-3 flex flex-wrap items-center gap-3">
          <form phx-change="search" onsubmit="return false" class="max-w-md flex-1">
            <input
              type="text"
              name="q"
              value={@search}
              placeholder="Search instance, version, location…"
              phx-debounce="300"
              class="w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </form>
          <div :if={length(@present_types) > 1} class="flex gap-2">
            <button
              :for={t <- @present_types}
              phx-click="type_filter"
              phx-value-type={t}
              class={chip(@type_filter == t)}
            >
              {t}
            </button>
          </div>
          <%!-- Two buttons with two DIFFERENT counts read as a riddle
               ("Series upgrade 1 selected" while 2 are selected) — say the
               selection once, name the action plainly, and let the series
               button explain why it covers fewer boxes. --%>
          <div :if={@writable and @selected_update_count > 0} class="ml-auto flex items-center gap-2">
            <span class="text-xs text-base-content/60">
              {@selected_update_count} selected:
            </span>
            <button
              phx-click="bulk_ask"
              phx-value-action="firmware_update"
              title={"Install the pending firmware update on the #{@selected_update_count} selected box(es). Stays on the current release series; a box may reboot to finish."}
              disabled={@bulk_busy}
              class="fw-bulk-update-btn rounded-lg bg-warning px-3 py-1.5 text-xs font-medium text-warning-content hover:bg-warning/80 disabled:opacity-50"
            >
              {if @bulk_busy, do: "Running…", else: "Update firmware"}
            </button>
            <button
              :if={@selected_series_count > 0}
              phx-click="bulk_ask"
              phx-value-action="firmware_upgrade"
              title={"Upgrade to the NEXT MAJOR VERSION (e.g. OPNsense 24.7 → 25.1, pfSense 2.7 → 2.8), not just the pending update. Only agent-mode boxes that report an upgrade target qualify — #{@selected_series_count} of the #{@selected_update_count} selected. Each box downloads the new release and reboots."}
              disabled={@bulk_busy}
              class="fw-bulk-upgrade-btn rounded-lg bg-error px-3 py-1.5 text-xs font-medium text-error-content hover:bg-error/80 disabled:opacity-50"
            >
              {cond do
                @bulk_busy ->
                  "Running…"

                @selected_series_count < @selected_update_count ->
                  "Major version upgrade (#{@selected_series_count} of #{@selected_update_count})"

                true ->
                  "Major version upgrade"
              end}
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

        <.empty_state :if={@rows == []} title="No push instances in your scope.">
          Firmware state is reported by the on-box agent; direct-API polled devices are not
          listed here.
        </.empty_state>
        <div :if={@rows != [] and @visible_rows == []} class="text-sm text-base-content/60">
          No matches.
        </div>

        <div :if={@visible_rows != []} class="overflow-x-auto rounded-lg border border-base-300">
          <table class="w-full min-w-[46rem] text-left text-sm">
            <thead class="bg-base-200 text-xs text-base-content/60">
              <tr>
                <th :if={@writable} class="px-3 py-2">
                  <input
                    type="checkbox"
                    phx-click="select_all"
                    checked={@all_eligible_selected}
                    title="Select all update-eligible rows"
                    aria-label="Select all update-eligible instances"
                    class="accent-primary"
                  />
                </th>
                <.sort_th col="state" label="State" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="instance" label="Instance" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="version" label="Version" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="latest" label="Latest" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="location" label="Location" sort_col={@sort_col} sort_dir={@sort_dir} />
                <th class="px-3 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              <%!-- fw-will-* mark the rows each bulk button would fire on;
                   hovering a button tints them (app.css :has() rule) so
                   "Major version upgrade (1 of 2)" shows WHICH one. --%>
              <tr
                :for={r <- @visible_rows}
                class={[
                  "border-b border-base-300/50 last:border-0",
                  MapSet.member?(@selected, r.id) && eligible?(r) && "fw-will-update",
                  MapSet.member?(@selected, r.id) && series_eligible?(r) && "fw-will-upgrade"
                ]}
              >
                <td :if={@writable} class="px-3 py-2">
                  <input
                    :if={eligible?(r)}
                    type="checkbox"
                    phx-click="toggle_select"
                    phx-value-id={r.id}
                    checked={MapSet.member?(@selected, r.id)}
                    aria-label={"Select #{r.name}"}
                    class="accent-primary"
                  />
                </td>
                <td class="px-3 py-2">
                  <span class={["rounded px-1.5 py-0.5 text-xs", state_class(r.state)]}>
                    {state_label(r.state)}
                  </span>
                  <span
                    :if={r.needs_reboot}
                    title="Reboot required to finish updates"
                    class="ml-1 text-warning"
                  >
                    ↻
                  </span>
                  <%!-- Without this the row is indistinguishable from a box
                       that really has an update waiting. --%>
                  <span
                    :if={r.check_failed}
                    title="The box could not reach its update repository — the pending-update state is unknown, not confirmed."
                    class="ml-1 rounded bg-base-300 px-1 py-0.5 text-[10px] text-base-content/70"
                  >
                    check failed
                  </span>
                </td>
                <td class="px-3 py-2">
                  <a href={~p"/instances/#{r.id}"} class="text-base-content hover:text-primary">
                    {r.name}
                  </a>
                  <span
                    :if={r.firmware_locked}
                    title="Firmware locked — excluded from update actions"
                    class="ml-1 text-base-content/60"
                  >
                    🔒
                  </span>
                  <.base_url_link base_url={r.base_url} />
                  <.webui_link instance_id={r.id} openable={r.gui_openable} />
                  <.shell_link instance_id={r.id} shell_enabled={r.shell_enabled} />
                  <div class="text-xs text-base-content/40">{r.device_type}</div>
                </td>
                <td class="px-3 py-2 font-mono text-xs text-base-content/70">{r.version}</td>
                <td class="px-3 py-2 font-mono text-xs text-base-content/60">{r.latest}</td>
                <td class="px-3 py-2 text-base-content/70">{r.location}</td>
                <td class="px-3 py-2 text-base-content/80">
                  {r.summary}
                  <span :if={r.security_updates > 0} class="ml-1 text-error">
                    ({r.security_updates} security)
                  </span>
                  <%!-- Same kind/key as the detail page's firmware comment,
                       so both surfaces show and edit the one row. --%>
                  <.comment_editor
                    text={CommentEditor.text(@comments, r.id, "firmware", "")}
                    writable={@writable}
                    instance_id={r.id}
                    kind="firmware"
                    entity_key=""
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
      <.confirm_dialog
        :if={@confirm}
        title={fw_bulk_title(@confirm.action, length(@confirm.names))}
        tier={if @confirm.action == "firmware_upgrade", do: :type_to_confirm, else: :danger}
        confirm_label={fw_bulk_title(@confirm.action, length(@confirm.names))}
        on_confirm="bulk_run"
        on_cancel="bulk_cancel"
        typed={@confirm_typed}
        must_type={to_string(length(@confirm.names))}
        items={@confirm.names}
      >
        {fw_bulk_consequence(@confirm.action, length(@confirm.names))}
      </.confirm_dialog>
    </main>
    """
  end

  defp bulk_target_names(assigns, action) do
    eligible = if action == "firmware_upgrade", do: &series_eligible?/1, else: &eligible?/1

    assigns
    |> visible()
    |> Enum.filter(eligible)
    |> Enum.filter(&MapSet.member?(assigns.selected, &1.id))
    |> Enum.map(& &1.name)
    |> Enum.sort()
  end

  defp fw_bulk_title("firmware_update", n), do: "Update firmware on #{n} instance(s)"
  defp fw_bulk_title("firmware_upgrade", n), do: "Major version upgrade on #{n} instance(s)"

  defp fw_bulk_consequence("firmware_update", _n),
    do: "Updates start immediately on the boxes below; some may reboot to finish."

  defp fw_bulk_consequence("firmware_upgrade", n),
    do:
      "Every box below downloads the next major release, installs it and REBOOTS; not undoable from here. Type #{n} to confirm."

  defp state_label(0), do: "OK"
  defp state_label(1), do: "UPDATE"
  defp state_label(2), do: "CRIT"
  defp state_label(_), do: "UNKNOWN"

  defp state_class(0), do: "bg-primary/20 text-primary"
  defp state_class(1), do: "bg-warning/20 text-warning"
  defp state_class(2), do: "bg-error/20 text-error"
  defp state_class(_), do: "bg-base-300 text-base-content/70"
end
