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
  needs-reboot/location columns, lock indicator and quick links.
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit
  import OrbitWeb.Components.CommentEditor, only: [comment_editor: 1]

  alias Orbit.Checks.Evaluate
  alias Orbit.Hub
  alias Orbit.Instances
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

  def handle_event("comment_save", params, socket),
    do: {:noreply, socket |> CommentEditor.save(params) |> load()}

  def handle_event("comment_clear", params, socket),
    do: {:noreply, socket |> CommentEditor.clear(params) |> load()}

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
          base_url: Orbit.Instances.Instance.primary_base_url(inst),
          version: fw["product_version"] || "—",
          latest: fw["product_latest"] || "",
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
    assigns =
      assign(assigns,
        visible_rows: visible(assigns),
        ok_count: Enum.count(assigns.rows, &(bucket(&1) == "ok")),
        update_count: Enum.count(assigns.rows, &(bucket(&1) == "update")),
        unknown_count: Enum.count(assigns.rows, &(bucket(&1) == "unknown")),
        present_types: assigns.rows |> Enum.map(& &1.device_type) |> Enum.uniq() |> Enum.sort()
      )

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
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
                <.sort_th col="state" label="State" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="instance" label="Instance" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="version" label="Version" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="latest" label="Latest" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="location" label="Location" sort_col={@sort_col} sort_dir={@sort_dir} />
                <th class="px-3 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={r <- @visible_rows} class="border-b border-base-300/50 last:border-0">
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
    </main>
    """
  end

  defp state_label(0), do: "OK"
  defp state_label(1), do: "UPDATE"
  defp state_label(2), do: "CRIT"
  defp state_label(_), do: "UNKNOWN"

  defp state_class(0), do: "bg-primary/20 text-primary"
  defp state_class(1), do: "bg-warning/20 text-warning"
  defp state_class(2), do: "bg-error/20 text-error"
  defp state_class(_), do: "bg-base-300 text-base-content/70"
end
