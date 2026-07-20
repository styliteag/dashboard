defmodule OrbitWeb.ConnectivityLive do
  @moduledoc """
  Fleet connectivity monitors — one row per configured ping monitor across the
  caller's visible push instances, read from the hub `connectivity` section and
  scored by the same connectivity check family (no reply ⇒ CRIT, misconfigured
  ⇒ WARN, 'none' skipped). RTT/loss come straight from the check metrics so the
  page agrees with Alerts and the exports. Worst-first, scoped (invariant 5);
  roster PubSub + 30s tier timer (monitors refresh at push cadence).
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit
  import OrbitWeb.Components.CommentEditor, only: [comment_editor: 1]
  import OrbitWeb.Components.ConnectivityMonitorDialog, only: [connectivity_monitor_dialog: 1]
  import OrbitWeb.Components.CheckHistoryDialog, only: [check_history_dialog: 1]

  alias Orbit.Auth.Scope
  alias OrbitWeb.Components.CommentEditor

  alias Orbit.Checks.Evaluate
  alias Orbit.Checks.History
  alias Orbit.Checks.ServiceCheck
  alias Orbit.Hub
  alias Orbit.Instances

  @refresh_ms 30_000

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
       writable: socket.assigns.current_user.role in ~w(admin user),
       conn_editor: nil,
       conn_test: nil,
       conn_test_busy: false,
       monitor_history: nil
     )
     |> load()}
  end

  @impl true
  def handle_event("search", %{"q" => q}, socket), do: {:noreply, assign(socket, search: q)}

  def handle_event("state_filter", %{"bucket" => b}, socket) when b in ~w(all ok warn crit) do
    b = if socket.assigns.state_filter == b, do: "all", else: b
    {:noreply, assign(socket, state_filter: b)}
  end

  def handle_event("row_gui_open", %{"id" => id}, socket) do
    {:noreply, gui_open_row(socket, id)}
  end

  # Editing a monitor from the FLEET view.
  #
  # `phx-value-iid` is rendered into the DOM, so its value is fully under the
  # visitor's control — "the row carries it" and "the browser sent it" are the
  # same thing. Nothing about the id can be trusted; what makes this safe is
  # that EVERY entry point re-resolves it through Scope.get_instance/2 with the
  # session's user, which answers nil for anything out of scope (invariant 1:
  # a user with zero groups sees NOTHING). Save/delete additionally require the
  # write role, and the SQL carries `WHERE id = ? AND instance_id = ?` so a
  # forged monitor id cannot reach across instances either.
  #
  # Do not "simplify" any of these back to using the id directly.
  def handle_event("conn_open", %{"iid" => raw_iid} = params, socket) do
    with true <- socket.assigns.writable,
         {iid, ""} <- Integer.parse(raw_iid),
         inst when not is_nil(inst) <- Scope.get_instance(iid, socket.assigns.current_user) do
      mon =
        case Integer.parse(to_string(params["id"] || "")) do
          {mid, ""} -> Enum.find(Orbit.Monitors.list_connectivity(inst.id), &(&1.id == mid))
          _ -> nil
        end

      editor = %{
        instance_id: inst.id,
        instance_name: inst.name,
        monitor_id: mon && mon.id,
        name: (mon && mon.name) || "",
        source: (mon && mon.source) || "",
        destination: (mon && mon.destination) || "",
        ping_count: (mon && mon.ping_count) || 3,
        enabled: is_nil(mon) or mon.enabled
      }

      {:noreply, assign(socket, conn_editor: editor, conn_test: nil)}
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("conn_cancel", _params, socket),
    do: {:noreply, assign(socket, conn_editor: nil, conn_test: nil)}

  def handle_event("conn_change", %{"monitor" => attrs}, socket) do
    case socket.assigns.conn_editor do
      nil ->
        {:noreply, socket}

      editor ->
        {:noreply,
         assign(socket,
           conn_editor: %{
             editor
             | name: attrs["name"] || "",
               source: attrs["source"] || "",
               destination: attrs["destination"] || "",
               ping_count: attrs["ping_count"] || editor.ping_count,
               enabled: attrs["enabled"] == "true"
           }
         )}
    end
  end

  # Write-gated too: a test sends real traffic from the operator's box, so it is
  # a mutation of the outside world even though it stores nothing. Today only a
  # writable user can open the dialog at all, but that is an indirect guarantee
  # — a crafted event must be refused on its own.
  def handle_event("conn_test", _params, socket) do
    editor = socket.assigns.conn_editor

    with true <- socket.assigns.writable,
         false <- socket.assigns.conn_test_busy,
         %{} <- editor,
         inst when not is_nil(inst) <-
           Scope.get_instance(editor.instance_id, socket.assigns.current_user) do
      {:noreply,
       socket
       |> assign(conn_test_busy: true, conn_test: nil)
       |> start_async(:conn_test, fn ->
         Orbit.Monitors.ping_test(inst, editor.source, editor.destination, editor.ping_count)
       end)}
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("conn_save", %{"monitor" => attrs}, socket) do
    editor = socket.assigns.conn_editor

    with true <- socket.assigns.writable,
         %{} <- editor,
         inst when not is_nil(inst) <-
           Scope.get_instance(editor.instance_id, socket.assigns.current_user) do
      result =
        case editor.monitor_id do
          nil -> Orbit.Monitors.create_connectivity(inst.id, attrs)
          mid -> Orbit.Monitors.update_connectivity(inst.id, mid, attrs)
        end

      case result do
        :ok ->
          {:noreply, socket |> assign(conn_editor: nil, conn_test: nil) |> load()}

        {:error, msg} ->
          {:noreply, assign(socket, conn_test: {:error, msg})}
      end
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("conn_delete", %{"id" => raw}, socket) do
    editor = socket.assigns.conn_editor

    with true <- socket.assigns.writable,
         %{} <- editor,
         {mid, ""} <- Integer.parse(raw),
         inst when not is_nil(inst) <-
           Scope.get_instance(editor.instance_id, socket.assigns.current_user) do
      :ok = Orbit.Monitors.delete_connectivity(inst.id, mid)
      {:noreply, socket |> assign(conn_editor: nil, conn_test: nil) |> load()}
    else
      _ -> {:noreply, socket}
    end
  end

  # Read-only, so no write-role gate — but the same id discipline as conn_open
  # above: the instance id comes from the DOM and is re-resolved through
  # Scope.get_instance/2, and the monitor id is only ever used as part of a
  # check key filtered by that resolved instance_id.
  def handle_event("monitor_history_open", %{"iid" => raw_iid, "id" => raw_id}, socket) do
    with {iid, ""} <- Integer.parse(raw_iid),
         inst when not is_nil(inst) <- Scope.get_instance(iid, socket.assigns.current_user),
         row when not is_nil(row) <- Enum.find(socket.assigns.rows, &row_match(&1, iid, raw_id)) do
      {:noreply,
       assign(socket,
         monitor_history: %{
           instance_name: inst.name,
           label: monitor_label(row),
           live_state: row.check.state,
           events: History.read(iid, to_string(row.check.key))
         }
       )}
    else
      _ -> {:noreply, socket}
    end
  end

  def handle_event("monitor_history_close", _params, socket),
    do: {:noreply, assign(socket, monitor_history: nil)}

  def handle_event("comment_save", params, socket),
    do: {:noreply, socket |> CommentEditor.save(params) |> load()}

  def handle_event("comment_clear", params, socket),
    do: {:noreply, socket |> CommentEditor.clear(params) |> load()}

  @impl true
  def handle_async(:conn_test, {:ok, result}, socket),
    do: {:noreply, assign(socket, conn_test_busy: false, conn_test: result)}

  def handle_async(:conn_test, {:exit, reason}, socket),
    do: {:noreply, assign(socket, conn_test_busy: false, conn_test: {:error, inspect(reason)})}

  @impl true
  def handle_info(:roster_changed, socket), do: {:noreply, load(socket)}

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  defp load(socket) do
    monitor_instances =
      socket.assigns.current_user
      |> Instances.list_visible()
      # Not agent_mode?: a Securepoint runs the same monitors over SSH.
      |> Enum.filter(&Instances.Instance.monitors_runnable?/1)

    rows =
      monitor_instances
      |> Enum.flat_map(fn inst ->
        monitors = Hub.cache_entry(inst.id)["connectivity"] || []

        gui_openable = Orbit.GUI.openable(inst) == :ok

        for check <- Evaluate.connectivity_checks(monitors) do
          %{
            instance_id: inst.id,
            instance_name: inst.name,
            shell_enabled: inst.shell_enabled,
            gui_openable: gui_openable,
            check: check,
            monitor_id: check.key |> to_string() |> String.replace_prefix("connectivity:", ""),
            rtt: metric_val(check, "ping_rtt_ms"),
            loss: metric_val(check, "ping_loss_pct")
          }
        end
      end)
      |> Enum.sort_by(fn %{check: c, instance_name: n} ->
        {-ServiceCheck.severity(c.state), n, c.key}
      end)

    assign(socket, rows: rows, comments: CommentEditor.lookup(monitor_instances))
  end

  defp visible(a) do
    q = String.downcase(a.search)

    a.rows
    |> Enum.filter(fn r ->
      q == "" or
        String.contains?(String.downcase(r.instance_name), q) or
        String.contains?(String.downcase(r.check.summary || ""), q)
    end)
    |> Enum.filter(fn r ->
      case a.state_filter do
        "all" -> true
        "ok" -> r.check.state == 0
        "warn" -> r.check.state in [1, 3]
        "crit" -> r.check.state == 2
      end
    end)
  end

  defp metric_val(%ServiceCheck{metrics: metrics}, name) do
    case Enum.find(metrics, &(&1.name == name)) do
      %{value: v} when is_number(v) -> v
      _ -> nil
    end
  end

  @impl true
  def render(assigns) do
    assigns =
      assign(assigns,
        visible_rows: visible(assigns),
        ok: Enum.count(assigns.rows, &(&1.check.state == 0)),
        warn: Enum.count(assigns.rows, &(&1.check.state in [1, 3])),
        crit: Enum.count(assigns.rows, &(&1.check.state == 2))
      )

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:connectivity} current_user={@current_user} />

      <section class="p-6">
        <h1 class="flex items-center gap-2 mb-4 text-lg font-medium text-base-content">
          <Icons.icon name={:connectivity} class="h-5 w-5 text-base-content/60" />
          Connectivity monitors
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
            label="OK"
            value={@ok}
            color="text-primary"
            event="state_filter"
            value_name="ok"
            active={@state_filter == "ok"}
          />
          <.kpi_tile
            label="WARN"
            value={@warn}
            color="text-warning"
            event="state_filter"
            value_name="warn"
            active={@state_filter == "warn"}
          />
          <.kpi_tile
            label="CRIT"
            value={@crit}
            color="text-error"
            event="state_filter"
            value_name="crit"
            active={@state_filter == "crit"}
          />
        </div>

        <form phx-change="search" onsubmit="return false" class="mb-3 max-w-md">
          <input
            type="text"
            name="q"
            value={@search}
            placeholder="Search instance, monitor…"
            phx-debounce="300"
            class="w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </form>

        <.empty_state :if={@rows == []} title="No connectivity monitors reported.">
          Monitors are configured per instance (Instance → Connectivity) and run on the box
          itself, so results appear here after the next agent push.
        </.empty_state>
        <div :if={@rows != [] and @visible_rows == []} class="text-sm text-base-content/60">
          No matches.
        </div>

        <div class="overflow-x-auto">
          <table :if={@visible_rows != []} class="w-full min-w-[46rem] text-left text-sm">
            <thead class="text-base-content/60">
              <tr class="border-b border-base-300">
                <th class="py-2 pr-4 font-medium">State</th>
                <th class="py-2 pr-4 font-medium">Instance</th>
                <th class="py-2 pr-4 font-medium">Monitor</th>
                <th class="py-2 pr-4 text-right font-medium">RTT</th>
                <th class="py-2 pr-4 text-right font-medium">Loss</th>
                <th class="py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={r <- @visible_rows} class="border-b border-base-300/50">
                <td class="py-2 pr-4">
                  <span class={["rounded px-1.5 py-0.5 text-xs", state_class(r.check.state)]}>
                    {state_label(r.check.state)}
                  </span>
                </td>
                <td class="py-2 pr-4">
                  <a
                    href={~p"/instances/#{r.instance_id}"}
                    class="text-base-content hover:text-primary"
                  >
                    {r.instance_name}
                  </a>
                  <.webui_link instance_id={r.instance_id} openable={r.gui_openable} />
                  <.shell_link instance_id={r.instance_id} shell_enabled={r.shell_enabled} />
                </td>
                <td class="py-2 pr-4 text-base-content/80">
                  <%!-- Display-only strip: every summary starts with the word
                     "Connectivity", redundant under this page's Monitor
                     column. The check engine's summary itself is untouched
                     (the four check surfaces keep their identical text). --%>
                  {String.replace_prefix(r.check.summary || "", "Connectivity ", "")}
                  <.comment_editor
                    text={CommentEditor.text(@comments, r.instance_id, "connectivity", r.monitor_id)}
                    writable={@writable}
                    instance_id={r.instance_id}
                    kind="connectivity"
                    entity_key={r.monitor_id}
                  />
                </td>
                <td class="py-2 pr-4 text-right text-base-content/70">{rtt_text(r.rtt)}</td>
                <td class="py-2 pr-4 text-right text-base-content/70">{loss_text(r.loss)}</td>
                <td class="py-2 text-right whitespace-nowrap">
                  <%!-- History is a read: no write role required, unlike Edit. --%>
                  <button
                    phx-click="monitor_history_open"
                    phx-value-iid={r.instance_id}
                    phx-value-id={r.monitor_id}
                    title="Recorded state transitions of this monitor"
                    class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
                  >
                    History
                  </button>
                  <button
                    :if={@writable}
                    phx-click="conn_open"
                    phx-value-iid={r.instance_id}
                    phx-value-id={r.monitor_id}
                    class="ml-1 rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
                  >
                    Edit
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <.connectivity_monitor_dialog
          editor={@conn_editor}
          busy={@conn_test_busy}
          result={@conn_test}
        />
        <.check_history_dialog history={@monitor_history} />
      </section>
    </main>
    """
  end

  defp row_match(row, iid, raw_id), do: row.instance_id == iid and row.monitor_id == raw_id

  # The Monitor column's text, minus the trailing live verdict — the dialog
  # shows the state itself in the lane, so repeating it in the title would go
  # stale the moment the monitor changes.
  defp monitor_label(row) do
    row.check.summary
    |> to_string()
    |> String.replace_prefix("Connectivity ", "")
    |> String.replace(~r/ ping (ok|FAILED.*|error.*)$/, "")
  end

  defp rtt_text(nil), do: "—"
  defp rtt_text(v) when is_number(v), do: "#{Float.round(v / 1, 1)} ms"

  defp loss_text(nil), do: "—"
  defp loss_text(v) when is_number(v), do: "#{Float.round(v / 1, 0)}%"

  defp state_label(0), do: "OK"
  defp state_label(1), do: "WARN"
  defp state_label(2), do: "CRIT"
  defp state_label(_), do: "UNKNOWN"

  defp state_class(0), do: "bg-primary/20 text-primary"
  defp state_class(1), do: "bg-warning/20 text-warning"
  defp state_class(2), do: "bg-error/20 text-error"
  defp state_class(_), do: "bg-base-300 text-base-content/70"
end
