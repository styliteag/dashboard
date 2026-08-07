defmodule OrbitWeb.LogEventsLive do
  @moduledoc """
  Fleet log events — the aggregated critical syslog events across the caller's
  visible push instances, worst-first (lowest syslog severity, then highest
  count). Read from the DB (Orbit.Logs.Store), which the hub refreshes on each
  hourly logfile push. Scoped through the instance list (invariant 5); a slow
  300s tier timer (logs move at push cadence, not live).
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit

  alias Orbit.Instances
  alias Orbit.Logs.Store

  @refresh_ms 300_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Process.send_after(self(), :refresh, @refresh_ms)
    # Errors first (python parity): the page exists to surface breakage, and
    # warning-level noise dominates an unfiltered fleet list.
    {:ok,
     socket
     |> assign(
       page_title: "Syslog",
       search: "",
       sev_filter: "err",
       tag_filter: "all",
       window: "all",
       sort_col: "sev",
       sort_dir: :asc,
       open_sample: nil
     )
     |> load()}
  end

  @impl true
  def handle_event("search", %{"q" => q}, socket), do: {:noreply, assign(socket, search: q)}

  def handle_event("sev_filter", %{"bucket" => b}, socket) when b in ~w(all crit err warn) do
    b = if socket.assigns.sev_filter == b, do: "all", else: b
    {:noreply, assign(socket, sev_filter: b)}
  end

  def handle_event("tag_filter", %{"tag" => tag}, socket) do
    tag = if socket.assigns.tag_filter == tag, do: "all", else: tag
    {:noreply, assign(socket, tag_filter: tag)}
  end

  # Availability-page parity (user request 2026-08-07): narrow to patterns
  # last seen inside the window. Filters only — the store keeps just the
  # latest push, there is no history to query.
  def handle_event("window", %{"window" => w}, socket) when w in ~w(24h 7d 30d all) do
    {:noreply, assign(socket, window: w)}
  end

  # Raw sample popover. Admin-only — the sample is un-masked raw log content
  # (CLAUDE.md invariant 4), so the toggle is refused for anyone else even
  # though the button is never rendered for them.
  def handle_event("toggle_sample", %{"id" => id}, socket) do
    if socket.assigns.current_user.role == "admin" do
      id = String.to_integer(id)
      open = if socket.assigns.open_sample == id, do: nil, else: id
      {:noreply, assign(socket, open_sample: open)}
    else
      {:noreply, socket}
    end
  end

  def handle_event("close_sample", _params, socket),
    do: {:noreply, assign(socket, open_sample: nil)}

  # Worst-first stays the DEFAULT; a header click overrides it for the
  # session (UI/UX review U-N1).
  def handle_event("sort", %{"col" => col}, socket)
      when col in ~w(sev instance program count last_seen) do
    dir =
      if socket.assigns.sort_col == col and socket.assigns.sort_dir == :asc,
        do: :desc,
        else: :asc

    {:noreply, socket |> assign(sort_col: col, sort_dir: dir) |> load()}
  end

  @impl true
  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  defp load(socket) do
    rows =
      socket.assigns.current_user
      |> Instances.list_visible()
      |> Enum.filter(&Instances.Instance.agent_mode?/1)
      |> Enum.flat_map(fn inst ->
        for e <- Store.list_events(inst.id), do: %{instance: inst, event: e}
      end)
      |> Enum.sort_by(sort_key(socket.assigns.sort_col), socket.assigns.sort_dir)

    assign(socket, rows: rows)
  end

  defp sort_key("sev"), do: fn %{instance: i, event: e} -> {e.severity, -e.count, i.name} end
  defp sort_key("instance"), do: fn r -> String.downcase(r.instance.name) end
  defp sort_key("program"), do: fn r -> String.downcase(r.event.program || "") end
  defp sort_key("count"), do: fn r -> r.event.count end

  # Unix seconds, not the DateTime struct: :asc/:desc compares structurally,
  # which mis-orders DateTimes across month boundaries. Sorts what the
  # column SHOWS (the parsed device stamp), ingest time as fallback.
  defp sort_key("last_seen") do
    fn r ->
      DateTime.to_unix(
        device_ts(r.event.last_ts) || r.event.updated_at || ~U[1970-01-01 00:00:00Z]
      )
    end
  end

  defp visible(rows, a) do
    q = String.downcase(a.search)

    rows
    |> Enum.filter(fn r ->
      q == "" or
        String.contains?(String.downcase(r.instance.name), q) or
        String.contains?(String.downcase(r.event.program || ""), q) or
        String.contains?(String.downcase(r.event.pattern || ""), q)
    end)
    |> Enum.filter(fn r ->
      case a.sev_filter do
        "all" -> true
        "crit" -> r.event.severity <= 2
        "err" -> r.event.severity == 3
        "warn" -> r.event.severity >= 4
      end
    end)
    |> Enum.filter(&(a.tag_filter == "all" or a.tag_filter in (&1.instance.tags || [])))
  end

  # Device syslog stamps are RFC3164 ("Aug  6 20:07:54") — no year, raw
  # device formatting, visibly different between boxes (user feedback
  # 2026-08-07: "datumsformat ist nicht immer gleich"). Parse into a
  # DateTime for the shared relative display; the raw stamp stays in the
  # tooltip because it is the device's own truth (device-local clock, so
  # the relative value is an approximation on the timezone-offset scale).
  # Year heuristic: current year, unless that lands in the future — then
  # the stamp is from December of last year.
  @months %{
    "Jan" => 1,
    "Feb" => 2,
    "Mar" => 3,
    "Apr" => 4,
    "May" => 5,
    "Jun" => 6,
    "Jul" => 7,
    "Aug" => 8,
    "Sep" => 9,
    "Oct" => 10,
    "Nov" => 11,
    "Dec" => 12
  }

  # ISO-8601 first (RFC5424 boxes — OPNsense syslog-ng/openvpn log
  # "2026-08-07T18:29:13+02:00"): the offset makes it EXACT, no year
  # heuristic needed. Prod feedback 2026-08-07: these fell through to the
  # raw string and the column showed three formats at once.
  @doc false
  def device_ts(ts) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, dt, _offset} -> DateTime.shift_zone!(dt, "Etc/UTC")
      _ -> rfc3164_ts(ts)
    end
  end

  def device_ts(_), do: nil

  defp rfc3164_ts(ts) do
    with [_, mon, d, h, mi, s] <-
           Regex.run(~r/^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/, ts),
         month when not is_nil(month) <- @months[mon],
         {:ok, naive} <-
           NaiveDateTime.new(
             DateTime.utc_now().year,
             month,
             String.to_integer(d),
             String.to_integer(h),
             String.to_integer(mi),
             String.to_integer(s)
           ) do
      dt = DateTime.from_naive!(naive, "Etc/UTC")

      # A stamp more than a day in the future cannot be this year.
      if DateTime.diff(dt, DateTime.utc_now()) > 86_400,
        do: %{dt | year: dt.year - 1},
        else: dt
    else
      _ -> nil
    end
  end

  # Newest ingest across the visible boxes — the age of everything on the page.
  defp last_ingest([]), do: nil

  defp last_ingest(rows) do
    rows
    |> Enum.map(& &1.event.updated_at)
    |> Enum.reject(&is_nil/1)
    |> case do
      [] -> nil
      stamps -> Enum.max(stamps, DateTime)
    end
  end

  # The window narrows BEFORE the KPI tiles count: tiles that contradict
  # the visible rows are exactly the trap the filter-notice work removed
  # (UI/UX review U-Q1).
  defp window_rows(rows, "all"), do: rows

  defp window_rows(rows, window) do
    secs = %{"24h" => 86_400, "7d" => 7 * 86_400, "30d" => 30 * 86_400}[window]
    now = DateTime.utc_now()

    Enum.filter(rows, fn r ->
      ts = device_ts(r.event.last_ts) || r.event.updated_at
      ts != nil and DateTime.diff(now, ts) <= secs
    end)
  end

  @impl true
  def render(assigns) do
    windowed = window_rows(assigns.rows, assigns.window)

    assigns =
      assign(assigns,
        windowed_rows: windowed,
        visible_rows: visible(windowed, assigns),
        crit: Enum.count(windowed, &(&1.event.severity <= 2)),
        err: Enum.count(windowed, &(&1.event.severity == 3)),
        warn: Enum.count(windowed, &(&1.event.severity >= 4)),
        tags: windowed |> Enum.flat_map(&(&1.instance.tags || [])) |> Enum.uniq() |> Enum.sort(),
        last_ingest: last_ingest(assigns.rows),
        admin?: assigns.current_user.role == "admin"
      )

    ~H"""
    <main id="main" class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:logs} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-2 flex flex-wrap items-center gap-3">
          <h1 class="flex items-center gap-2 text-xl font-semibold text-base-content">
            <Icons.icon name={:logs} class="h-5 w-5 text-base-content/70" /> Syslog
            <span class="ml-2 text-sm text-base-content/70">({length(@rows)})</span>
          </h1>
          <%!-- Availability-page parity (user request 2026-08-07): narrow to
               patterns last seen inside the window. --%>
          <div class="ml-auto flex items-center gap-1">
            <button
              :for={key <- ~w(24h 7d 30d all)}
              phx-click="window"
              phx-value-window={key}
              class={[
                "rounded px-2 py-0.5 text-xs",
                if(@window == key,
                  do: "bg-base-300 text-base-content",
                  else: "text-base-content/70 hover:bg-base-300/60"
                )
              ]}
            >
              {key}
            </button>
          </div>
        </div>

        <.data_note>
          Warning-or-worse syslog lines from your agent-mode boxes, worst first — not a live
          viewer. Each hourly push <em>replaces</em>
          a box's events; identical lines are
          normalised and counted, so a row is a pattern, not one occurrence.
          <span :if={@last_ingest} title={ts_abs(@last_ingest)}>
            Newest ingest: {ts_rel(@last_ingest)} — an idle box keeps its
            last push.
          </span>
        </.data_note>

        <div class="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4 sm:gap-3">
          <.kpi_tile
            label="Total"
            value={length(@windowed_rows)}
            event="sev_filter"
            value_name="all"
            active={@sev_filter == "all"}
          />
          <.kpi_tile
            label="CRIT"
            value={@crit}
            color="text-error"
            event="sev_filter"
            value_name="crit"
            active={@sev_filter == "crit"}
          />
          <.kpi_tile
            label="ERR"
            value={@err}
            color="text-orange-400"
            event="sev_filter"
            value_name="err"
            active={@sev_filter == "err"}
          />
          <.kpi_tile
            label="WARN"
            value={@warn}
            color="text-warning"
            event="sev_filter"
            value_name="warn"
            active={@sev_filter == "warn"}
          />
        </div>

        <%!-- The page mounts pre-filtered to ERR; without this line the
             Total tile contradicts the visible rows (UI/UX review U-Q1).
             The window counts as a filter too. --%>
        <.filter_notice
          :if={@sev_filter != "all" or @window != "all"}
          shown={length(@visible_rows)}
          total={length(@rows)}
          noun="log patterns"
          filter_label={
            [
              if(@sev_filter != "all", do: String.upcase(@sev_filter)),
              if(@window != "all", do: "last #{@window}")
            ]
            |> Enum.reject(&is_nil/1)
            |> Enum.join(" · ")
          }
          event="sev_filter"
        />

        <div class="mb-3 flex flex-wrap items-center gap-3">
          <form phx-change="search" onsubmit="return false" class="max-w-md flex-1">
            <input
              type="text"
              name="q"
              value={@search}
              placeholder="Search instance, program, pattern…"
              phx-debounce="300"
              class="w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </form>
          <div :if={@tags != []} class="flex flex-wrap gap-2">
            <button
              :for={tag <- @tags}
              phx-click="tag_filter"
              phx-value-tag={tag}
              class={chip(@tag_filter == tag)}
            >
              {tag}
            </button>
          </div>
        </div>

        <.empty_state :if={@rows == []} title="No log events at or above the severity floor.">
          Agents push their logfiles about once an hour and only warning-or-worse lines are
          kept — a quiet fleet legitimately shows nothing here.
        </.empty_state>
        <div :if={@rows != [] and @visible_rows == []} class="text-sm text-base-content/70">
          No matches.
        </div>

        <div class="overflow-x-auto">
          <table :if={@visible_rows != []} class="w-full min-w-[46rem] text-left text-sm">
            <thead class="sticky top-0 z-10 bg-base-100 text-base-content/70">
              <tr class="border-b border-base-300">
                <.sort_th col="sev" label="Sev" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th
                  col="instance"
                  label="Instance"
                  sort_col={@sort_col}
                  sort_dir={@sort_dir}
                />
                <.sort_th col="program" label="Program" sort_col={@sort_col} sort_dir={@sort_dir} />
                <th scope="col" class="py-2 pr-4 font-medium">Pattern</th>
                <.sort_th col="count" label="Count" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th
                  col="last_seen"
                  label="Last seen"
                  sort_col={@sort_col}
                  sort_dir={@sort_dir}
                />
              </tr>
            </thead>
            <tbody>
              <%= for r <- @visible_rows do %>
                <tr class="border-b border-base-300/50">
                  <td class="py-2 pr-4">
                    <span class={["rounded px-1.5 py-0.5 text-xs", sev_class(r.event.severity)]}>
                      {sev_label(r.event.severity)}
                    </span>
                  </td>
                  <td class="py-2 pr-4">
                    <a
                      href={~p"/instances/#{r.instance.id}"}
                      class="text-base-content hover:text-primary"
                    >
                      {r.instance.name}
                    </a>
                  </td>
                  <td class="py-2 pr-4 text-base-content/70">{r.event.program}</td>
                  <td class="py-2 pr-4 text-base-content/80">
                    {r.event.pattern}
                    <button
                      :if={@admin? and (r.event.sample || "") != ""}
                      phx-click="toggle_sample"
                      phx-value-id={r.event.id}
                      title="Show the raw (un-masked) log line for this pattern — admin only"
                      class="ml-2 rounded border border-base-content/20 px-1 py-0 align-middle text-[10px] text-base-content/70 hover:bg-base-300 hover:text-base-content/80"
                    >
                      raw
                    </button>
                  </td>
                  <td class="py-2 pr-4 text-right text-base-content/80">{r.event.count}</td>
                  <td
                    class="whitespace-nowrap py-2 pr-4 text-base-content/70"
                    title={"#{r.event.last_ts} (device clock)"}
                  >
                    {case device_ts(r.event.last_ts) do
                      nil -> r.event.last_ts
                      dt -> ts_rel(dt)
                    end}
                  </td>
                </tr>
                <%!-- Raw un-masked sample line for this pattern (admin only —
                     invariant 4). Full-width row, not a floating popover, so
                     the overflow-x container can never clip it. --%>
                <tr
                  :if={@admin? and @open_sample == r.event.id}
                  class="border-b border-base-300/50 bg-base-200/40"
                >
                  <td colspan="6" class="px-3 py-2">
                    <div class="mb-1 flex items-center justify-between text-[11px] text-base-content/70">
                      <span>Raw sample · {r.event.log_name} · last seen {r.event.last_ts}</span>
                      <button phx-click="close_sample" class="hover:text-base-content/80">
                        ✕ close
                      </button>
                    </div>
                    <pre class="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-base-300/50 p-2 font-mono text-xs text-base-content/80">{r.event.sample}</pre>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>
      </section>
    </main>
    """
  end

  # Syslog severity: 0 emerg … 4 warning (lower = worse; nothing >4 is stored).
  defp sev_label(s) when s <= 2, do: "CRIT"
  defp sev_label(3), do: "ERR"
  defp sev_label(_), do: "WARN"

  defp sev_class(s) when s <= 2, do: "bg-error/20 text-error"
  defp sev_class(3), do: "bg-orange-900/50 text-orange-300"
  defp sev_class(_), do: "bg-warning/20 text-warning"
end
