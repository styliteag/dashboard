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
    {:ok, socket |> assign(search: "", sev_filter: "all", instance_filter: "all") |> load()}
  end

  @impl true
  def handle_event("search", %{"q" => q}, socket), do: {:noreply, assign(socket, search: q)}

  def handle_event("sev_filter", %{"bucket" => b}, socket) when b in ~w(all crit err warn) do
    b = if socket.assigns.sev_filter == b, do: "all", else: b
    {:noreply, assign(socket, sev_filter: b)}
  end

  def handle_event("instance_filter", %{"name" => name}, socket) do
    name = if socket.assigns.instance_filter == name, do: "all", else: name
    {:noreply, assign(socket, instance_filter: name)}
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
      |> Enum.sort_by(fn %{instance: i, event: e} -> {e.severity, -e.count, i.name} end)

    assign(socket, rows: rows)
  end

  defp visible(a) do
    q = String.downcase(a.search)

    a.rows
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
    |> Enum.filter(&(a.instance_filter == "all" or &1.instance.name == a.instance_filter))
  end

  # Which daemons are noisy, worst severity first — the shape of the noise
  # before the first row. Top 8 keeps the row scannable; the count in the note
  # says how many were left out rather than silently truncating.
  defp program_tally(rows) do
    rows
    |> Enum.reject(&(&1.event.program in [nil, ""]))
    |> Enum.group_by(& &1.event.program)
    |> Enum.map(fn {program, list} ->
      %{
        program: program,
        count: Enum.sum(Enum.map(list, & &1.event.count)),
        tone: tone_for(Enum.min_by(list, & &1.event.severity).event.severity)
      }
    end)
    |> Enum.sort_by(&{-&1.count, &1.program})
  end

  # Syslog severity is inverted: lower number = worse.
  defp tone_for(sev) when sev <= 2, do: :crit
  defp tone_for(3), do: :warn
  defp tone_for(_), do: :neutral

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

  @impl true
  def render(assigns) do
    assigns =
      assign(assigns,
        visible_rows: visible(assigns),
        crit: Enum.count(assigns.rows, &(&1.event.severity <= 2)),
        err: Enum.count(assigns.rows, &(&1.event.severity == 3)),
        warn: Enum.count(assigns.rows, &(&1.event.severity >= 4)),
        instance_names:
          assigns.rows |> Enum.map(& &1.instance.name) |> Enum.uniq() |> Enum.sort(),
        programs: program_tally(assigns.rows),
        last_ingest: last_ingest(assigns.rows)
      )

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:logs} current_user={@current_user} />

      <section class="p-6">
        <h1 class="flex items-center gap-2 mb-2 text-lg font-medium text-base-content">
          <Icons.icon name={:logs} class="h-5 w-5 text-base-content/60" /> Log events
          <span class="ml-2 text-sm text-base-content/60">({length(@rows)})</span>
        </h1>

        <.data_note>
          Aggregated syslog lines of your agent-mode boxes, worst severity first. This is not a
          log viewer: agents push their logfiles about once an hour, each push <em>replaces</em>
          the events of that box, and only severity 4 (warning) or worse is kept at all —
          everything quieter is dropped at ingest and can never appear here. Identical lines are
          normalised (IPs and numbers masked) and counted, so one row is a pattern, not an
          occurrence. Real fleets legitimately show zero CRIT rows.
          <span :if={@last_ingest}>
            Newest ingest: {Calendar.strftime(@last_ingest, "%Y-%m-%d %H:%M UTC")} — an idle box
            keeps showing its last push.
          </span>
        </.data_note>

        <div class="mb-4 grid gap-3 sm:grid-cols-4">
          <.kpi_tile
            label="Total"
            value={length(@rows)}
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
          <div :if={length(@instance_names) > 1} class="flex flex-wrap gap-2">
            <button
              :for={name <- @instance_names}
              phx-click="instance_filter"
              phx-value-name={name}
              class={chip(@instance_filter == name)}
            >
              {name}
            </button>
          </div>
        </div>

        <div :if={@programs != []} class="mb-3 flex flex-wrap gap-2">
          <.count_chip
            :for={p <- Enum.take(@programs, 8)}
            label={p.program}
            count={p.count}
            tone={p.tone}
            title="lines counted for this program, toned by its worst severity"
          />
          <span :if={length(@programs) > 8} class="self-center text-xs text-base-content/50">
            +{length(@programs) - 8} more programs, see the table
          </span>
        </div>

        <.empty_state :if={@rows == []} title="No log events at or above the severity floor.">
          Agents push their logfiles about once an hour and only warning-or-worse lines are
          kept — a quiet fleet legitimately shows nothing here.
        </.empty_state>
        <div :if={@rows != [] and @visible_rows == []} class="text-sm text-base-content/60">
          No matches.
        </div>

        <div class="overflow-x-auto">
          <table :if={@visible_rows != []} class="w-full min-w-[46rem] text-left text-sm">
            <thead class="sticky top-0 z-10 bg-base-100 text-base-content/60">
              <tr class="border-b border-base-300">
                <th class="py-2 pr-4 font-medium">Sev</th>
                <th class="py-2 pr-4 font-medium">Instance</th>
                <th class="py-2 pr-4 font-medium">Program</th>
                <th class="py-2 pr-4 font-medium">Pattern</th>
                <th class="py-2 pr-4 text-right font-medium">Count</th>
                <th class="py-2 pr-4 font-medium">Last seen</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={r <- @visible_rows} class="border-b border-base-300/50">
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
                <td class="py-2 pr-4 text-base-content/80">{r.event.pattern}</td>
                <td class="py-2 pr-4 text-right text-base-content/80">{r.event.count}</td>
                <td class="py-2 pr-4 text-base-content/60">{r.event.last_ts}</td>
              </tr>
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
