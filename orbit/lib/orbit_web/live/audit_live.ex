defmodule OrbitWeb.AuditLive do
  @moduledoc """
  Audit surface with two tabs (DR-AL9 — no extra nav entry):

  - **Actions** — the mutation trail (audit_log rows, colour-coded result).
  - **Access** — who uses the dashboard (DR-AL7): summary aggregates
    (online sessions, logins 24h, blocks by reason, busiest principals)
    over the merged chronological timeline (auth events, instance
    accesses, geoip/crowdsec denials, sampled requests). Request samples
    default OFF in the filter (polling noise).

  Gate is on_mount(:require_admin_or_superadmin) — DR-AL1: the superadmin's
  role is view_only, plain require_admin would lock them out of exactly
  their oversight domain. Refreshes on the 30s standard tier.
  """

  use OrbitWeb, :live_view

  alias Orbit.Access

  @limit 100
  @refresh_ms 30_000

  @timeline_types [
    {:auth, "Logins"},
    {:access, "Instance access"},
    {:denial, "Blocked"},
    {:request, "Requests"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Process.send_after(self(), :refresh, @refresh_ms)

    socket =
      socket
      |> assign(
        tab: :actions,
        types: MapSet.new([:auth, :access, :denial]),
        q: "",
        hours: nil,
        grouped: false,
        action_q: "",
        action_hours: nil,
        action_limit: 100
      )
      |> load()

    {:ok, socket}
  end

  @impl true
  def handle_event("tab", %{"tab" => tab}, socket) when tab in ["actions", "access"] do
    {:noreply, socket |> assign(tab: String.to_existing_atom(tab)) |> load()}
  end

  def handle_event("toggle_type", %{"type" => type}, socket) do
    type = String.to_existing_atom(type)
    types = socket.assigns.types

    types =
      if MapSet.member?(types, type),
        do: MapSet.delete(types, type),
        else: MapSet.put(types, type)

    {:noreply, socket |> assign(types: types) |> load()}
  end

  def handle_event("action_filter", params, socket) do
    hours =
      case Integer.parse(to_string(params["hours"] || "")) do
        {h, ""} when h > 0 -> h
        _ -> nil
      end

    {:noreply,
     socket
     |> assign(action_q: params["q"] || "", action_hours: hours, action_limit: 100)
     |> load()}
  end

  def handle_event("action_more", _params, socket) do
    {:noreply, socket |> assign(action_limit: socket.assigns.action_limit + 200) |> load()}
  end

  def handle_event("refresh", _params, socket) do
    {:noreply, load(socket)}
  end

  def handle_event("filter", params, socket) do
    hours =
      case Integer.parse(params["hours"] || "") do
        {n, ""} when n > 0 -> n
        _ -> nil
      end

    {:noreply,
     socket
     |> assign(q: params["q"] || "", hours: hours, grouped: params["grouped"] == "true")
     |> load()}
  end

  @impl true
  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, load(socket)}
  end

  defp load(%{assigns: %{tab: :access}} = socket) do
    types = MapSet.to_list(socket.assigns.types)
    opts = [q: socket.assigns.q, hours: socket.assigns.hours]

    socket = assign(socket, summary: Access.summary())

    if socket.assigns.grouped do
      assign(socket, grouped_rows: Access.grouped(types, @limit, opts), timeline: [])
    else
      assign(socket, timeline: Access.timeline(types, @limit, opts), grouped_rows: [])
    end
  end

  defp load(socket) do
    a = socket.assigns

    assign(socket,
      rows:
        load_rows(
          a[:action_q] || "",
          a[:action_hours],
          a[:action_limit] || @limit,
          a.current_user
        )
    )
  end

  # Actions-tab filters (AuditPage parity): free-text on action/target,
  # hours window, load-more pagination; user_id resolves to the username.
  defp load_rows(q, hours, limit, current_user) do
    {where, params} =
      []
      |> then(fn acc ->
        if q != "",
          do: [{"(action LIKE ? OR target_type LIKE ?)", ["%#{q}%", "%#{q}%"]} | acc],
          else: acc
      end)
      |> then(fn acc ->
        case hours do
          h when is_integer(h) and h > 0 ->
            cutoff =
              DateTime.utc_now()
              |> DateTime.add(-h * 3600)
              |> DateTime.to_naive()
              |> NaiveDateTime.truncate(:second)

            [{"ts >= ?", [cutoff]} | acc]

          _ ->
            acc
        end
      end)
      |> Enum.reduce({[], []}, fn {frag, ps}, {fs, all} -> {[frag | fs], all ++ ps} end)

    where_sql = if where == [], do: "", else: " WHERE " <> Enum.join(where, " AND ")

    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT ts, action, result, user_id, target_type, target_id, source_ip " <>
          "FROM audit_log" <> where_sql <> " ORDER BY id DESC LIMIT #{limit}",
        params
      )

    usernames = usernames_by_id()
    instance_names = instance_names(current_user)

    for [ts, action, result, user_id, ttype, tid, ip] <- rows do
      %{
        ts: ts,
        action: action,
        result: result,
        user: usernames[user_id] || (user_id && "##{user_id}") || "—",
        target: target(ttype, tid, instance_names),
        ip: ip,
        geo: OrbitWeb.Geo.label(ip)
      }
    end
  end

  defp usernames_by_id do
    Orbit.Repo.query!("SELECT id, username FROM users").rows
    |> Map.new(fn [id, name] -> {id, name} end)
  rescue
    _ -> %{}
  end

  # Names only for instances the viewer's groups allow (stricter than the
  # page gate on purpose): out-of-scope targets keep the raw "instance:N".
  defp instance_names(user) do
    Orbit.Instances.Instance
    |> Orbit.Auth.Scope.scope(user)
    |> Orbit.Repo.all()
    |> Map.new(&{&1.id, &1.name})
  rescue
    _ -> %{}
  end

  defp target(nil, _, _), do: "—"
  defp target(t, nil, _), do: t

  # target_id is stored as a string (Audit.write to_string's it) — parse
  # before the integer-keyed name lookup or nothing ever matches.
  defp target("instance", id, names) do
    with {n, ""} <- Integer.parse(to_string(id)),
         name when is_binary(name) <- names[n] do
      "#{name} (##{id})"
    else
      _ -> "instance:#{id}"
    end
  end

  defp target(t, id, _), do: "#{t}:#{id}"

  @impl true
  def render(assigns) do
    assigns = Phoenix.Component.assign(assigns, :timeline_types, @timeline_types)

    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:audit} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:audit} class="h-5 w-5 text-base-content/60" /> Audit
          </h1>
          <div class="flex rounded border border-base-300 text-xs">
            <button
              :for={{tab, label} <- [{:actions, "Actions"}, {:access, "Access"}]}
              phx-click="tab"
              phx-value-tab={tab}
              class={[
                "px-3 py-1",
                @tab == tab && "bg-base-300 text-base-content",
                @tab != tab && "text-base-content/70 hover:text-base-content"
              ]}
            >
              {label}
            </button>
          </div>
          <button
            phx-click="refresh"
            class="rounded border border-base-content/20 px-2 py-1 text-xs text-base-content/70 hover:bg-base-300"
          >
            Refresh
          </button>
        </div>

        <div :if={@tab == :actions}>
          <form
            phx-change="action_filter"
            onsubmit="return false"
            class="mb-3 flex flex-wrap items-center gap-2"
          >
            <input
              type="text"
              name="q"
              value={@action_q}
              placeholder="Filter action or target…"
              phx-debounce="300"
              class="max-w-xs flex-1 rounded-lg border border-base-content/20 bg-base-300 px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
            />
            <select
              name="hours"
              class="rounded-lg border border-base-content/20 bg-base-300 px-2 py-1.5 text-sm text-base-content/80"
            >
              <option value="" selected={@action_hours == nil}>All time</option>
              <option :for={h <- [1, 6, 24, 168]} value={h} selected={@action_hours == h}>
                last {h}h
              </option>
            </select>
          </form>
          <div class="overflow-x-auto">
            <table class="w-full min-w-[46rem] text-left text-sm">
              <thead class="sticky top-0 z-10 bg-base-100 text-base-content/60">
                <tr class="border-b border-base-300">
                  <th class="py-2 pr-4 font-medium">Time (UTC)</th>
                  <th class="py-2 pr-4 font-medium">Action</th>
                  <th class="py-2 pr-4 font-medium">Result</th>
                  <th class="py-2 pr-4 font-medium">User</th>
                  <th class="py-2 pr-4 font-medium">Target</th>
                  <th class="py-2 pr-4 font-medium">IP</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={r <- @rows} class="border-b border-base-300/50">
                  <td class="py-2 pr-4 font-mono text-xs text-base-content/60">{fmt_ts(r.ts)}</td>
                  <td class="py-2 pr-4 text-base-content/80">{r.action}</td>
                  <td class="py-2 pr-4">
                    <span class={["rounded px-1.5 py-0.5 text-xs", result_class(r.result)]}>
                      {r.result}
                    </span>
                  </td>
                  <td class="py-2 pr-4 text-base-content/70">{r.user}</td>
                  <td class="py-2 pr-4 text-base-content/70">{r.target}</td>
                  <%!-- GeoIP tag next to the address (3.1.7 parity): the
                       footer already resolved the viewer's own IP, but the
                       audit rows — where an unfamiliar address actually
                       matters — showed a bare number. nil for private and
                       unknown addresses, so nothing is invented. --%>
                  <td class="py-2 pr-4 text-base-content/60">
                    {r.ip || "—"}
                    <span :if={r.geo} class="ml-1 text-xs text-base-content/40">{r.geo}</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <button
            :if={length(@rows) >= @action_limit}
            phx-click="action_more"
            class="mt-3 rounded border border-base-content/20 px-3 py-1 text-xs text-base-content/70 hover:bg-base-300"
          >
            Load more
          </button>
        </div>

        <div :if={@tab == :access}>
          <div class="mb-6 grid gap-4 md:grid-cols-4">
            <div class="rounded-lg border border-base-300 bg-base-200 p-4">
              <div class="text-xs text-base-content/60">Online now</div>
              <div class="mt-1 text-2xl text-primary">{length(@summary.online)}</div>
              <div :for={s <- Enum.take(@summary.online, 5)} class="mt-1 text-xs text-base-content/70">
                {s.username || "user ##{s.user_id}"} · {s.ip}
              </div>
            </div>
            <div class="rounded-lg border border-base-300 bg-base-200 p-4">
              <div class="text-xs text-base-content/60">Logins (24h)</div>
              <div class="mt-1 text-2xl text-base-content">
                {@summary.logins_24h.ok}
                <span :if={@summary.logins_24h.failed > 0} class="text-base text-error">
                  / {@summary.logins_24h.failed} failed
                </span>
              </div>
            </div>
            <div class="rounded-lg border border-base-300 bg-base-200 p-4">
              <div class="text-xs text-base-content/60">Blocked (all time)</div>
              <div class="mt-1 text-2xl text-error">
                {@summary.blocks |> Enum.map(& &1.count) |> Enum.sum()}
              </div>
              <div :for={b <- Enum.take(@summary.blocks, 4)} class="mt-1 text-xs text-base-content/70">
                {b.reason} · {b.count}
              </div>
            </div>
            <div class="rounded-lg border border-base-300 bg-base-200 p-4">
              <div class="text-xs text-base-content/60">Requests (24h)</div>
              <div :for={p <- Enum.take(@summary.principals_24h, 5)} class="mt-1 text-xs">
                <span class="text-base-content/80">{p.principal}</span>
                <span class="text-base-content/60"> · {p.count}</span>
              </div>
            </div>
          </div>

          <div class="mb-3 flex flex-wrap items-center gap-2 text-xs">
            <span class="text-base-content/60">Show:</span>
            <button
              :for={{type, label} <- @timeline_types}
              phx-click="toggle_type"
              phx-value-type={type}
              class={[
                "rounded border px-2 py-0.5",
                MapSet.member?(@types, type) && "border-primary/60 text-primary",
                !MapSet.member?(@types, type) && "border-base-content/20 text-base-content/60"
              ]}
            >
              {label}
            </button>
            <form phx-change="filter" phx-submit="filter" class="ml-2 flex items-center gap-2">
              <input
                type="text"
                name="q"
                value={@q}
                placeholder="search user / ip / text…"
                phx-debounce="400"
                class="w-48 rounded border border-base-content/20 bg-base-100 px-2 py-0.5 text-xs text-base-content"
              />
              <select
                name="hours"
                class="rounded border border-base-content/20 bg-base-100 px-1 py-0.5 text-xs text-base-content/80"
              >
                <option value="" selected={@hours == nil}>all time</option>
                <option value="24" selected={@hours == 24}>24h</option>
                <option value="168" selected={@hours == 168}>7d</option>
                <option value="720" selected={@hours == 720}>30d</option>
              </select>
              <label class="flex items-center gap-1 text-base-content/70">
                <input type="hidden" name="grouped" value="false" />
                <input
                  type="checkbox"
                  name="grouped"
                  value="true"
                  checked={@grouped}
                  class="accent-primary"
                /> grouped
              </label>
            </form>
          </div>

          <div class="overflow-x-auto">
            <table :if={@grouped} class="w-full min-w-[46rem] text-left text-sm">
              <thead class="sticky top-0 z-10 bg-base-100 text-base-content/60">
                <tr class="border-b border-base-300">
                  <th class="py-2 pr-4 font-medium">Count</th>
                  <th class="py-2 pr-4 font-medium">Type</th>
                  <th class="py-2 pr-4 font-medium">Who</th>
                  <th class="py-2 pr-4 font-medium">Event (numbers masked)</th>
                  <th class="py-2 font-medium">Last seen</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={g <- @grouped_rows} class="border-b border-base-300/50">
                  <td class="py-1.5 pr-4 text-right text-base-content/80">{g.count}</td>
                  <td class="py-1.5 pr-4">
                    <span class={["rounded px-1.5 py-0.5 text-xs", type_class(g.type)]}>
                      {type_label(g.type)}
                    </span>
                  </td>
                  <td class="py-1.5 pr-4 text-base-content/80">{g.who}</td>
                  <td class="py-1.5 pr-4 text-base-content/70">{g.text}</td>
                  <td class="py-1.5 font-mono text-xs text-base-content/60">{fmt_ts(g.last_ts)}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={@grouped and @grouped_rows == []} class="py-4 text-sm text-base-content/60">
            No events for the selected filters.
          </div>

          <div class="overflow-x-auto">
            <table :if={not @grouped} class="w-full min-w-[46rem] text-left text-sm">
              <thead class="sticky top-0 z-10 bg-base-100 text-base-content/60">
                <tr class="border-b border-base-300">
                  <th class="py-2 pr-4 font-medium">Time (UTC)</th>
                  <th class="py-2 pr-4 font-medium">Type</th>
                  <th class="py-2 pr-4 font-medium">Who</th>
                  <th class="py-2 pr-4 font-medium">IP</th>
                  <th class="py-2 pr-4 font-medium">Event</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={e <- @timeline} class="border-b border-base-300/50">
                  <td class="py-2 pr-4 font-mono text-xs text-base-content/60">{fmt_ts(e.ts)}</td>
                  <td class="py-2 pr-4">
                    <span class={["rounded px-1.5 py-0.5 text-xs", type_class(e.type)]}>
                      {type_label(e.type)}
                    </span>
                  </td>
                  <td class="py-2 pr-4 text-base-content/80">{e.who}</td>
                  <td class="py-2 pr-4 text-base-content/60">{e.ip || "—"}</td>
                  <td class="py-2 pr-4 text-base-content/70">{e.text}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={not @grouped and @timeline == []} class="py-4 text-sm text-base-content/60">
            No events for the selected types.
          </div>
        </div>
      </section>
    </main>
    """
  end

  defp fmt_ts(%NaiveDateTime{} = ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  defp fmt_ts(%DateTime{} = ts), do: Calendar.strftime(ts, "%Y-%m-%d %H:%M:%S")
  defp fmt_ts(other), do: to_string(other)

  defp result_class("ok"), do: "bg-primary/20 text-primary"
  defp result_class("pending"), do: "bg-base-300 text-base-content/70"
  defp result_class("denied"), do: "bg-error/20 text-error"
  defp result_class(_), do: "bg-warning/20 text-warning"

  defp type_label(:login_ok), do: "LOGIN"
  defp type_label(:login_fail), do: "LOGIN FAIL"
  defp type_label(:logout), do: "LOGOUT"
  defp type_label(:session_expired), do: "EXPIRED"
  defp type_label(:denial), do: "BLOCKED"
  defp type_label(:access), do: "ACCESS"
  defp type_label(:request), do: "REQ"

  defp type_class(:login_ok), do: "bg-primary/20 text-primary"
  defp type_class(:login_fail), do: "bg-error/20 text-error"
  defp type_class(:denial), do: "bg-error/20 text-error"
  defp type_class(:access), do: "bg-info/20 text-info"
  defp type_class(:request), do: "bg-neutral text-base-content/70"
  defp type_class(_), do: "bg-warning/20 text-warning"
end
