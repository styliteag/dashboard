defmodule OrbitWeb.CertificatesLive do
  @moduledoc """
  Fleet certificate expiry — every certificate across the caller's visible
  push instances with its days-remaining verdict, read from the hub
  certificates section. The verdict uses the same cert check family (CRIT
  when expired or <7d, WARN <30d) so it agrees with Alerts and the exports.
  Worst-first, scoped through the instance list (invariant 5); roster PubSub
  + 60s tier timer (certs move slowly).

  Interaction parity with CertificatesPage.tsx: KPI tiles as verdict
  filters, search, sortable columns, issuer/expiry/days columns with an
  expiry-runway bar, GUI/CA badges and quick links.
  """

  use OrbitWeb, :live_view

  import OrbitWeb.Components.ListKit
  import OrbitWeb.Components.CommentEditor, only: [comment_editor: 1]

  alias Orbit.Checks.ServiceCheck
  alias OrbitWeb.Components.CommentEditor
  alias Orbit.Hub
  alias Orbit.Instances

  @refresh_ms 60_000
  @sort_cols ~w(state instance name issuer days)
  # ACME renews at 30 days by default; a cert still unrenewed at 21 means the
  # automation has already missed its window (python _CERT_ACME_RENEW_DAYS).
  @acme_renew_days 21
  # Full runway = a fresh 1-year cert; the bar clamps there.
  @runway_days 365

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
       # Soonest expiry first: the page exists to answer "what runs out
       # next", and the state sort already exists one click away.
       sort_col: "days",
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
      when b in ~w(all crit warn ok acme) do
    b = if socket.assigns.state_filter == b, do: "all", else: b
    {:noreply, assign(socket, state_filter: b)}
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
    rows =
      socket.assigns.current_user
      |> Instances.list_visible()
      # No agent-mode filter: a polled box reports certificates too, and the
      # per-instance tab has always shown them (same reasoning as the export
      # fix — one fleet view, every transport).
      |> Enum.flat_map(fn inst ->
        certs = Hub.cache_entry(inst.id)["certificates"] || []
        gui_openable = Orbit.GUI.openable(inst) == :ok

        for c <- certs, is_number(c["days_remaining"]) do
          %{
            instance_id: inst.id,
            instance_name: inst.name,
            shell_enabled: inst.shell_enabled,
            gui_openable: gui_openable,
            base_url: inst.base_url,
            name: c["name"] || c["subject"] || "cert",
            refid: to_string(c["refid"] || c["name"] || ""),
            issuer: c["issuer"] || "",
            not_after: c["not_after"] || "",
            days: trunc(c["days_remaining"]),
            is_gui: c["is_gui"] == true,
            is_ca: to_string(c["type"] || "") == "ca",
            acme: acme?(c["issuer"]),
            # An ACME cert inside its renew window that has NOT been renewed
            # means the automation is failing — the strongest "Let's Encrypt
            # is broken here" signal, and it fires long before the 30-day
            # expiry warning would.
            acme_overdue: acme_overdue?(c["issuer"], c["days_remaining"]),
            # Same thresholds as Evaluate.cert_checks (@cert_crit_days 7 /
            # @cert_warn_days 30) — keep in sync, four-surface parity.
            state: days_state(c["days_remaining"])
          }
        end
      end)
      |> Enum.sort_by(fn r -> {-ServiceCheck.severity(r.state), r.instance_name, r.name} end)

    assign(socket,
      rows: rows,
      comments: CommentEditor.lookup(Instances.list_visible(socket.assigns.current_user))
    )
  end

  # Issuers whose certs are renewed by ACME automation (python
  # _ACME_ISSUER_MARKERS, verbatim).
  @acme_markers [
    "let's encrypt",
    "lets encrypt",
    "isrg",
    "zerossl",
    "buypass",
    "google trust services"
  ]

  @doc false
  def acme?(issuer) when is_binary(issuer) do
    lower = String.downcase(issuer)
    Enum.any?(@acme_markers, &String.contains?(lower, &1))
  end

  def acme?(_), do: false

  @doc """
  An ACME certificate that should already have been renewed.

  ACME clients renew at 30 days; one still standing at #{@acme_renew_days}
  means the automation missed its window — a broken-renewal signal that
  fires ~3 weeks before the generic expiry warning. Expired certs are NOT
  "overdue": they read as expired, which is the louder verdict already.
  """
  def acme_overdue?(issuer, days) when is_number(days),
    do: acme?(issuer) and days >= 0 and days < @acme_renew_days

  def acme_overdue?(_issuer, _days), do: false

  defp days_state(days) when days < 7, do: 2
  defp days_state(days) when days < 30, do: 1
  defp days_state(_), do: 0

  defp visible(a) do
    q = String.downcase(a.search)

    a.rows
    |> Enum.filter(fn r ->
      q == "" or
        String.contains?(String.downcase(r.instance_name), q) or
        String.contains?(String.downcase(r.name), q) or
        String.contains?(String.downcase(r.issuer), q)
    end)
    |> Enum.filter(fn r ->
      case a.state_filter do
        "all" -> true
        "acme" -> r.acme_overdue
        "crit" -> r.state == 2
        "warn" -> r.state == 1
        "ok" -> r.state == 0
      end
    end)
    |> Enum.sort_by(sort_key(a.sort_col), a.sort_dir)
  end

  defp sort_key("state") do
    fn r -> {-ServiceCheck.severity(r.state), String.downcase(r.instance_name)} end
  end

  defp sort_key("instance"), do: fn r -> String.downcase(r.instance_name) end
  defp sort_key("name"), do: fn r -> String.downcase(r.name) end
  defp sort_key("issuer"), do: fn r -> String.downcase(r.issuer) end
  defp sort_key("days"), do: fn r -> r.days end

  @impl true
  def render(assigns) do
    assigns =
      assign(assigns,
        visible_rows: visible(assigns),
        crit: Enum.count(assigns.rows, &(&1.state == 2)),
        warn: Enum.count(assigns.rows, &(&1.state == 1)),
        acme_overdue: Enum.count(assigns.rows, & &1.acme_overdue),
        ok: Enum.count(assigns.rows, &(&1.state == 0))
      )

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:certificates} current_user={@current_user} />

      <section class="p-6">
        <h1 class="flex items-center gap-2 mb-4 text-lg font-medium text-base-content">
          <Icons.icon name={:certificates} class="h-5 w-5 text-base-content/60" /> Certificates
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
            label="Expired / <7d"
            value={@crit}
            color="text-error"
            event="state_filter"
            value_name="crit"
            active={@state_filter == "crit"}
          />
          <.kpi_tile
            label="Expiring <30d"
            value={@warn}
            color="text-warning"
            event="state_filter"
            value_name="warn"
            active={@state_filter == "warn"}
          />
          <%!-- Renewal overdue: an ACME cert that should already have been
               renewed. Fires ~3 weeks before the generic expiry warning
               would, and points at broken automation rather than at a cert
               someone forgot. --%>
          <.kpi_tile
            label="Renewal overdue"
            value={@acme_overdue}
            color="text-error"
            event="state_filter"
            value_name="acme"
            active={@state_filter == "acme"}
          />
          <.kpi_tile
            label="Healthy"
            value={@ok}
            color="text-primary"
            event="state_filter"
            value_name="ok"
            active={@state_filter == "ok"}
          />
        </div>

        <form phx-change="search" onsubmit="return false" class="mb-3 max-w-md">
          <input
            type="text"
            name="q"
            value={@search}
            placeholder="Search instance, certificate, issuer…"
            phx-debounce="300"
            class="w-full rounded-lg border border-base-content/20 bg-base-300 px-3 py-2 text-sm focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </form>

        <.empty_state :if={@rows == []} title="No certificates reported.">
          Certificates come from the boxes themselves — a firewall that has not pushed yet, or
          one outside your groups, shows nothing here.
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
                <.sort_th col="name" label="Certificate" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="issuer" label="Issuer" sort_col={@sort_col} sort_dir={@sort_dir} />
                <.sort_th col="days" label="Expires" sort_col={@sort_col} sort_dir={@sort_dir} />
                <th class="px-3 py-2 font-medium">Runway</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={r <- @visible_rows} class="border-b border-base-300/50 last:border-0">
                <td class="px-3 py-2">
                  <span class={["rounded px-1.5 py-0.5 text-xs", state_class(r.state)]}>
                    {state_label(r.state)}
                  </span>
                </td>
                <td class="px-3 py-2">
                  <a
                    href={~p"/instances/#{r.instance_id}"}
                    class="text-base-content hover:text-primary"
                  >
                    {r.instance_name}
                  </a>
                  <.base_url_link base_url={r.base_url} />
                  <.webui_link instance_id={r.instance_id} openable={r.gui_openable} />
                  <.shell_link instance_id={r.instance_id} shell_enabled={r.shell_enabled} />
                </td>
                <td class="px-3 py-2 text-base-content/80">
                  {r.name}
                  <.comment_editor
                    text={CommentEditor.text(@comments, r.instance_id, "cert", r.refid)}
                    writable={@writable}
                    instance_id={r.instance_id}
                    kind="cert"
                    entity_key={r.refid}
                  />
                  <span
                    :if={r.acme}
                    title={
                      if r.acme_overdue,
                        do:
                          "ACME certificate past its renewal window — the automation is probably failing.",
                        else: "Renewed automatically via ACME."
                    }
                    class={[
                      "ml-1 rounded px-1 py-0.5 text-[10px]",
                      if(r.acme_overdue,
                        do: "bg-error/20 text-error",
                        else: "bg-base-300 text-base-content/60"
                      )
                    ]}
                  >
                    {if r.acme_overdue, do: "ACME overdue", else: "ACME"}
                  </span>
                  <span
                    :if={r.is_gui}
                    class="ml-1 rounded bg-info/20 px-1 py-0.5 text-[10px] text-info"
                  >
                    GUI
                  </span>
                  <span
                    :if={r.is_ca}
                    class="ml-1 rounded bg-neutral px-1 py-0.5 text-[10px] text-base-content/70"
                  >
                    CA
                  </span>
                </td>
                <td class="px-3 py-2 text-xs text-base-content/60">{r.issuer}</td>
                <td class="px-3 py-2 text-base-content/70" title={r.not_after}>
                  <span :if={r.days < 0} class="text-error">expired {-r.days}d ago</span>
                  <span :if={r.days >= 0}>{r.days}d</span>
                </td>
                <td class="px-3 py-2">
                  <div class="h-1.5 w-24 overflow-hidden rounded bg-base-300">
                    <div
                      class={["h-full", runway_color(r.state)]}
                      style={"width: #{runway_pct(r.days)}%"}
                    >
                    </div>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>
    """
  end

  defp runway_pct(days) do
    days |> max(0) |> min(@runway_days) |> Kernel.*(100) |> div(@runway_days)
  end

  defp runway_color(2), do: "bg-error"
  defp runway_color(1), do: "bg-warning"
  defp runway_color(_), do: "bg-primary"

  defp state_label(0), do: "OK"
  defp state_label(1), do: "EXPIRING"
  defp state_label(2), do: "CRIT"
  defp state_label(_), do: "UNKNOWN"

  defp state_class(0), do: "bg-primary/20 text-primary"
  defp state_class(1), do: "bg-warning/20 text-warning"
  defp state_class(2), do: "bg-error/20 text-error"
  defp state_class(_), do: "bg-base-300 text-base-content/70"
end
